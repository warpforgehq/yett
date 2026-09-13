use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};

use age::secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::access::AccessList;
use crate::error::Error;
use crate::identity::{resolve_identity_path, IdentityStore, PassphrasePrompt};

pub const DEFAULT_TIER: &str = "dev";
pub const YETT_DIR: &str = ".yett";
pub const ACCESS_PATH: &str = ".yett/secrets-access.yaml";
pub const SOPS_CONFIG_PATH: &str = ".sops.yaml";
pub const ENV_REFS_PATH: &str = ".env.refs";

const ACCESS_TEMPLATE: &str = "version: 1\npeople: []\n";

pub const ENV_REFS_TEMPLATE: &str = "\
# yett environment references. Values starting with `ref+` are resolved when
# the process starts and injected into its environment.
# DATABASE_URL=ref+sops://.yett/secrets.dev.enc.yaml#/db/url
";

#[derive(Debug)]
pub struct InitOutput {
    pub tiers: Vec<String>,
    pub access_path: PathBuf,
    pub sops_path: PathBuf,
    pub env_refs_path: PathBuf,
}

#[derive(Debug)]
pub struct KeygenOutput {
    pub tier: String,
    pub path: PathBuf,
    pub public_key: String,
    pub yaml_line: String,
}

#[derive(Debug)]
pub struct RegisterOutput {
    pub tier: String,
    pub handle: String,
    pub path: PathBuf,
    pub public_key: String,
    pub reused: bool,
}

#[derive(Debug)]
pub struct InitWithHandleOutput {
    pub init: InitOutput,
    pub register: RegisterOutput,
}

pub fn parse_tiers(spec: &str) -> Result<Vec<String>, Error> {
    let mut tiers: Vec<String> = Vec::new();
    for raw in spec.split(',') {
        let tier = raw.trim();
        validate_tier(tier)?;
        if tiers.iter().any(|seen| seen == tier) {
            return Err(Error::Usage(format!("duplicate tier `{tier}`")));
        }
        tiers.push(tier.to_string());
    }
    Ok(tiers)
}

pub fn validate_tier(tier: &str) -> Result<(), Error> {
    if tier.is_empty() {
        return Err(Error::Usage("tier must not be empty".to_string()));
    }
    if !tier
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(Error::Usage(format!(
            "invalid tier name `{tier}`; use letters, digits, `_` and `-`"
        )));
    }
    Ok(())
}

pub fn init(root: &Path, tiers: &[String]) -> Result<InitOutput, Error> {
    let access_path = root.join(ACCESS_PATH);
    let sops_path = root.join(SOPS_CONFIG_PATH);
    let env_refs_path = root.join(ENV_REFS_PATH);

    let directory = root.join(YETT_DIR);
    let directory_created = !directory.exists();
    std::fs::create_dir_all(&directory)
        .map_err(|error| Error::Usage(format!("cannot create {}: {error}", directory.display())))?;

    let mut created: Vec<PathBuf> = Vec::new();
    let outcome = (|| -> Result<(), Error> {
        create_new_file(&access_path, ACCESS_TEMPLATE, &mut created)?;
        create_new_file(&env_refs_path, ENV_REFS_TEMPLATE, &mut created)?;
        let access =
            AccessList::load(&access_path).map_err(|error| Error::Usage(error.to_string()))?;
        create_new_file(&sops_path, &access.render_sops_config(), &mut created)?;
        Ok(())
    })();

    if let Err(error) = outcome {
        for path in created.iter().rev() {
            let _ = std::fs::remove_file(path);
        }
        if directory_created {
            let _ = std::fs::remove_dir(&directory);
        }
        return Err(error);
    }

    Ok(InitOutput {
        tiers: tiers.to_vec(),
        access_path,
        sops_path,
        env_refs_path,
    })
}

fn create_new_file(path: &Path, contents: &str, created: &mut Vec<PathBuf>) -> Result<(), Error> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                Error::Usage(format!(
                    "{} already exists; refusing to overwrite",
                    path.display()
                ))
            } else {
                Error::Usage(format!("cannot write {}: {error}", path.display()))
            }
        })?;
    created.push(path.to_path_buf());
    file.write_all(contents.as_bytes())
        .map_err(|error| Error::Usage(format!("cannot write {}: {error}", path.display())))?;
    file.sync_all()
        .map_err(|error| Error::Usage(format!("cannot write {}: {error}", path.display())))
}

pub fn keygen(
    tier: &str,
    prompt: &mut dyn PassphrasePrompt,
    work_factor: Option<u8>,
) -> Result<KeygenOutput, Error> {
    validate_tier(tier)?;
    let path = default_identity_path(tier)?;
    refuse_existing(&path)?;

    let passphrase = prompt.prompt(tier)?;
    let confirmation = prompt.confirm(tier)?;
    if passphrase.is_empty() {
        return Err(Error::Usage(
            "the passphrase is empty; nothing was written".to_string(),
        ));
    }
    if *passphrase != *confirmation {
        return Err(Error::Usage(
            "the passphrases do not match; nothing was written".to_string(),
        ));
    }

    let identity = age::x25519::Identity::generate();
    let public_key = identity.to_public().to_string();
    let secret = identity.to_string();
    let ciphertext = encrypt_identity(secret.expose_secret().as_bytes(), &passphrase, work_factor)?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            Error::Usage(format!("cannot create {}: {error}", parent.display()))
        })?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).map_err(
            |error| Error::Usage(format!("cannot restrict {}: {error}", parent.display())),
        )?;
    }
    write_private(&path, &ciphertext)?;

    Ok(KeygenOutput {
        tier: tier.to_string(),
        path,
        public_key: public_key.clone(),
        yaml_line: format!("      {tier}: {public_key}"),
    })
}

pub fn write_sops_config(access: &AccessList, root: &Path) -> Result<(), Error> {
    crate::access::write_atomic(&root.join(SOPS_CONFIG_PATH), &access.render_sops_config())
}

pub fn keygen_register(
    tier: &str,
    handle: &str,
    root: &Path,
    prompt: &mut dyn PassphrasePrompt,
    work_factor: Option<u8>,
) -> Result<RegisterOutput, Error> {
    validate_tier(tier)?;
    let access_path = root.join(ACCESS_PATH);
    let mut access = AccessList::load(&access_path).map_err(|error| {
        Error::Usage(format!("{error}; run `yett init` to create {ACCESS_PATH}"))
    })?;

    let path = default_identity_path(tier)?;
    let (public_key, path, reused) = if path.exists() {
        let identity = IdentityStore::new()
            .load(tier, Some(&path), prompt)
            .map_err(Error::from)?;
        (identity.recipient().to_string(), path, true)
    } else {
        let created = keygen(tier, prompt, work_factor)?;
        (created.public_key, created.path, false)
    };

    access
        .add(handle, tier, &public_key)
        .map_err(|error| Error::Usage(error.to_string()))?;
    access
        .save(&access_path)
        .map_err(|error| Error::Usage(error.to_string()))?;
    write_sops_config(&access, root)?;

    Ok(RegisterOutput {
        tier: tier.to_string(),
        handle: handle.to_string(),
        path,
        public_key,
        reused,
    })
}

pub fn init_with_handle(
    root: &Path,
    tiers: &str,
    handle: &str,
    prompt: &mut dyn PassphrasePrompt,
    work_factor: Option<u8>,
) -> Result<InitWithHandleOutput, Error> {
    init_with_handle_impl(root, tiers, handle, prompt, work_factor, stdin_is_tty())
}

fn init_with_handle_impl(
    root: &Path,
    tiers: &str,
    handle: &str,
    prompt: &mut dyn PassphrasePrompt,
    work_factor: Option<u8>,
    stdin_is_tty: bool,
) -> Result<InitWithHandleOutput, Error> {
    let tiers = parse_tiers(tiers)?;
    if tiers.len() != 1 {
        return Err(Error::Usage(format!(
            "`--handle` needs exactly one tier, but got {}; run `yett keygen --register {handle} --tier <tier>` once per tier",
            tiers.join(", ")
        )));
    }
    if !stdin_is_tty {
        return Err(Error::Usage(format!(
            "standard input is not a terminal; run `yett init` then `yett keygen --register {handle} --tier <tier>`"
        )));
    }
    let init = init(root, &tiers)?;
    let tier = &tiers[0];
    let register = keygen_register(tier, handle, root, prompt, work_factor)
        .map_err(|error| resume_error(error, handle, tier))?;
    Ok(InitWithHandleOutput { init, register })
}

fn resume_error(error: Error, handle: &str, tier: &str) -> Error {
    let hint = format!("resume with `yett keygen --register {handle} --tier {tier}`");
    match error {
        Error::Usage(message) => Error::Usage(format!("{message}\n{hint}")),
        Error::Decryption(message) => Error::Decryption(format!("{message}\n{hint}")),
        Error::Unresolved(message) => Error::Unresolved(format!("{message}\n{hint}")),
        Error::AccessMismatch(message) => Error::AccessMismatch(format!("{message}\n{hint}")),
        other => other,
    }
}

fn stdin_is_tty() -> bool {
    unsafe { libc::isatty(libc::STDIN_FILENO) == 1 }
}

fn refuse_existing(path: &Path) -> Result<(), Error> {
    if path.exists() {
        return Err(Error::Usage(format!(
            "{} already exists; refusing to overwrite",
            path.display()
        )));
    }
    Ok(())
}

fn default_identity_path(tier: &str) -> Result<PathBuf, Error> {
    let xdg = non_empty(std::env::var_os("XDG_CONFIG_HOME"));
    let home = non_empty(std::env::var_os("HOME"));
    if xdg.is_none() && home.is_none() {
        return Err(Error::Usage(
            "cannot determine the default identity path: set XDG_CONFIG_HOME or HOME".to_string(),
        ));
    }
    Ok(resolve_identity_path(
        tier,
        None,
        None,
        xdg.as_deref(),
        home.as_deref(),
    ))
}

fn non_empty(value: Option<OsString>) -> Option<PathBuf> {
    value.filter(|value| !value.is_empty()).map(PathBuf::from)
}

fn encrypt_identity(
    plaintext: &[u8],
    passphrase: &str,
    work_factor: Option<u8>,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut recipient = age::scrypt::Recipient::new(SecretString::from(passphrase.to_owned()));
    if let Some(work_factor) = work_factor {
        recipient.set_work_factor(work_factor);
    }
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .map_err(|error| Error::Usage(format!("cannot encrypt the identity: {error}")))?;

    let mut out = Zeroizing::new(Vec::new());
    {
        let mut writer = encryptor
            .wrap_output(&mut *out)
            .map_err(|error| Error::Usage(format!("cannot encrypt the identity: {error}")))?;
        writer
            .write_all(plaintext)
            .map_err(|error| Error::Usage(format!("cannot encrypt the identity: {error}")))?;
        writer
            .finish()
            .map_err(|error| Error::Usage(format!("cannot encrypt the identity: {error}")))?;
    }
    Ok(out)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                Error::Usage(format!(
                    "{} already exists; refusing to overwrite",
                    path.display()
                ))
            } else {
                Error::Usage(format!("cannot write {}: {error}", path.display()))
            }
        })?;
    file.write_all(bytes)
        .map_err(|error| Error::Usage(format!("cannot write {}: {error}", path.display())))?;
    file.sync_all()
        .map_err(|error| Error::Usage(format!("cannot write {}: {error}", path.display())))
}

#[cfg(test)]
mod tests;
