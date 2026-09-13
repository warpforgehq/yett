use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use age::secrecy::SecretString;
use zeroize::Zeroizing;

use crate::harden::SecretBuf;

pub const IDENTITY_ENV: &str = "YETT_IDENTITY";

const SECRET_KEY_PREFIX: &str = "AGE-SECRET-KEY-1";
const AGE_BINARY_HEADER: &[u8] = b"age-encryption.org/v1";
const AGE_ARMOR_HEADER: &[u8] = b"-----BEGIN AGE ENCRYPTED FILE-----";

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("malformed age secret key: {0}")]
    MalformedKey(&'static str),
    #[error("cannot read identity file {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("plaintext key at the default identity path {0}; it must be passphrase-encrypted")]
    PlaintextAtDefaultPath(PathBuf),
    #[error("identity file {0} is neither an age ciphertext nor an AGE-SECRET-KEY-1 line")]
    UnrecognizedFormat(PathBuf),
    #[error("decrypted identity {0} holds no AGE-SECRET-KEY-1 line")]
    NoKeyInPayload(PathBuf),
    #[error("cannot decrypt identity {path}: {source}")]
    Decrypt {
        path: PathBuf,
        source: age::DecryptError,
    },
    #[error("cannot prompt for the {tier} passphrase on the terminal: {source}")]
    Prompt {
        tier: String,
        source: std::io::Error,
    },
}

pub struct Identity {
    secret: SecretBuf,
    recipient: String,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Identity(<redacted>)")
    }
}

impl Identity {
    pub fn from_secret_key(key: &str) -> Result<Self, IdentityError> {
        let secret = SecretBuf::new(key.trim());
        let parsed = age::x25519::Identity::from_str(secret.as_str())
            .map_err(IdentityError::MalformedKey)?;
        let recipient = parsed.to_public().to_string();
        Ok(Identity { secret, recipient })
    }

    pub(crate) fn expose(&self) -> &str {
        self.secret.as_str()
    }

    pub(crate) fn recipient(&self) -> &str {
        &self.recipient
    }
}

pub type Passphrase = Zeroizing<String>;

pub trait PassphrasePrompt {
    fn prompt(&mut self, tier: &str) -> Result<Passphrase, IdentityError>;

    fn confirm(&mut self, tier: &str) -> Result<Passphrase, IdentityError> {
        self.prompt(tier)
    }
}

pub struct TtyPrompt;

impl PassphrasePrompt for TtyPrompt {
    fn prompt(&mut self, tier: &str) -> Result<Passphrase, IdentityError> {
        rpassword::prompt_password(format!("yett: passphrase for the {tier} identity: "))
            .map(Zeroizing::new)
            .map_err(|source| IdentityError::Prompt {
                tier: tier.to_string(),
                source,
            })
    }

    fn confirm(&mut self, tier: &str) -> Result<Passphrase, IdentityError> {
        rpassword::prompt_password(format!("yett: confirm the {tier} passphrase: "))
            .map(Zeroizing::new)
            .map_err(|source| IdentityError::Prompt {
                tier: tier.to_string(),
                source,
            })
    }
}

pub fn resolve_identity_path(
    tier: &str,
    explicit: Option<&Path>,
    env: Option<&OsStr>,
    xdg_config_home: Option<&Path>,
    home: Option<&Path>,
) -> PathBuf {
    if let Some(path) = explicit {
        return path.to_path_buf();
    }
    if let Some(path) = env {
        return PathBuf::from(path);
    }

    let file = format!("{tier}.key.age");
    match xdg_config_home {
        Some(xdg) => xdg.join("yett").join(file),
        None => home
            .unwrap_or_else(|| Path::new(""))
            .join(".config")
            .join("yett")
            .join(file),
    }
}

pub fn tier_from_secret_path(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    let tier = name.strip_prefix("secrets.")?.strip_suffix(".enc.yaml")?;
    (!tier.is_empty()).then(|| tier.to_string())
}

#[derive(Default)]
pub struct IdentityStore {
    cache: Mutex<HashMap<String, Arc<Identity>>>,
}

impl IdentityStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load(
        &self,
        tier: &str,
        explicit: Option<&Path>,
        prompt: &mut dyn PassphrasePrompt,
    ) -> Result<Arc<Identity>, IdentityError> {
        if let Some(cached) = self.cached(tier) {
            return Ok(cached);
        }

        let env = std::env::var_os(IDENTITY_ENV);
        let named_explicitly = explicit.is_some() || env.is_some();
        let path = resolve_identity_path(
            tier,
            explicit,
            env.as_deref(),
            std::env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .as_deref(),
            std::env::var_os("HOME").map(PathBuf::from).as_deref(),
        );

        let identity = Arc::new(read_identity(&path, tier, named_explicitly, prompt)?);

        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        Ok(Arc::clone(
            cache.entry(tier.to_string()).or_insert(identity),
        ))
    }

    fn cached(&self, tier: &str) -> Option<Arc<Identity>> {
        let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.get(tier).map(Arc::clone)
    }
}

fn read_identity(
    path: &Path,
    tier: &str,
    named_explicitly: bool,
    prompt: &mut dyn PassphrasePrompt,
) -> Result<Identity, IdentityError> {
    let bytes = Zeroizing::new(std::fs::read(path).map_err(|source| IdentityError::Read {
        path: path.to_path_buf(),
        source,
    })?);

    if is_age_ciphertext(&bytes) {
        let passphrase = prompt.prompt(tier)?;
        let payload = SecretBuf::from_zeroizing(decrypt_identity(&bytes, &passphrase, path)?);
        let key = secret_key_line(payload.as_bytes())
            .ok_or_else(|| IdentityError::NoKeyInPayload(path.to_path_buf()))?;
        return Identity::from_secret_key(key);
    }

    match secret_key_line(&bytes) {
        None => Err(IdentityError::UnrecognizedFormat(path.to_path_buf())),
        Some(_) if !named_explicitly => {
            Err(IdentityError::PlaintextAtDefaultPath(path.to_path_buf()))
        }
        Some(key) => Identity::from_secret_key(key),
    }
}

fn is_age_ciphertext(bytes: &[u8]) -> bool {
    bytes.starts_with(AGE_BINARY_HEADER) || bytes.starts_with(AGE_ARMOR_HEADER)
}

fn secret_key_line(bytes: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(bytes).ok()?;
    text.lines()
        .map(str::trim)
        .find(|line| line.starts_with(SECRET_KEY_PREFIX))
}

fn decrypt_identity(
    bytes: &[u8],
    passphrase: &str,
    path: &Path,
) -> Result<Zeroizing<Vec<u8>>, IdentityError> {
    let failed = |source| IdentityError::Decrypt {
        path: path.to_path_buf(),
        source,
    };

    let scrypt = age::scrypt::Identity::new(SecretString::from(passphrase.to_owned()));
    let decryptor = age::Decryptor::new(age::armor::ArmoredReader::new(bytes)).map_err(failed)?;
    let mut reader = decryptor
        .decrypt(std::iter::once(&scrypt as &dyn age::Identity))
        .map_err(failed)?;

    let mut payload = Zeroizing::new(Vec::new());
    reader
        .read_to_end(&mut payload)
        .map_err(|source| IdentityError::Read {
            path: path.to_path_buf(),
            source,
        })?;

    Ok(payload)
}

#[cfg(test)]
mod tests;
