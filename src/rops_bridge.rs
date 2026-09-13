use std::ffi::OsString;
use std::fmt::Display;
use std::str::FromStr;
use std::sync::{Mutex, MutexGuard};

use rops::cryptography::{cipher::AES256GCM, hasher::SHA512};
use rops::file::builder::RopsFileBuilder;
use rops::file::format::YamlFileFormat;
use rops::file::state::{DecryptedFile, EncryptedFile};
use rops::file::RopsFile;
use rops::integration::{AgeIntegration, Integration};

use crate::identity::Identity;

const NO_SUCH_KEY_FILE: &str = "/nonexistent/yett/no-rops-age-key-file";
const SOPS_VERSION: &str = "3.8.1";

fn with_sops_version(text: &str) -> Result<String, BridgeError> {
    let mut document: serde_yaml::Value = serde_yaml::from_str(text).map_err(|error| {
        BridgeError::Encrypt(format!("cannot reparse the emitted sops document: {error}"))
    })?;
    let metadata = document
        .as_mapping_mut()
        .and_then(|mapping| mapping.get_mut(serde_yaml::Value::String("sops".into())))
        .and_then(serde_yaml::Value::as_mapping_mut)
        .ok_or_else(|| {
            BridgeError::Encrypt("the emitted sops document has no sops metadata".into())
        })?;
    metadata.insert(
        serde_yaml::Value::String("version".into()),
        serde_yaml::Value::String(SOPS_VERSION.into()),
    );
    serde_yaml::to_string(&document).map_err(|error| {
        BridgeError::Encrypt(format!("cannot serialize the sops document: {error}"))
    })
}

type EncryptedYaml = RopsFile<EncryptedFile<AES256GCM, SHA512>, YamlFileFormat>;
type DecryptedYaml = RopsFile<DecryptedFile<SHA512>, YamlFileFormat>;

#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    #[error("sops encryption failed: {0}")]
    Encrypt(String),
    #[error("sops decryption failed: {0}")]
    Decrypt(String),
}

fn encrypt_error(e: impl Display) -> BridgeError {
    BridgeError::Encrypt(e.to_string())
}

fn decrypt_error(e: impl Display) -> BridgeError {
    BridgeError::Decrypt(e.to_string())
}

fn reject_sops_key(plaintext: &str) -> Result<(), BridgeError> {
    let document: serde_yaml::Value = serde_yaml::from_str(plaintext).map_err(encrypt_error)?;
    if document
        .as_mapping()
        .map(|mapping| mapping.contains_key(serde_yaml::Value::String("sops".into())))
        .unwrap_or(false)
    {
        return Err(BridgeError::Encrypt(
            "the plaintext defines a top-level `sops` key, which collides with the SOPS metadata"
                .to_string(),
        ));
    }
    Ok(())
}

fn rops_lock() -> MutexGuard<'static, ()> {
    static ROPS_LOCK: Mutex<()> = Mutex::new(());
    ROPS_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

struct EnvGuard {
    saved: [(String, Option<OsString>); 2],
}

impl EnvGuard {
    fn install(secret: &str) -> Self {
        let key = AgeIntegration::private_key_env_var_name();
        let key_file = AgeIntegration::private_key_file_path_override_env_var_name();
        let saved = [
            (key.clone(), std::env::var_os(&key)),
            (key_file.clone(), std::env::var_os(&key_file)),
        ];
        std::env::set_var(&key, secret);
        std::env::set_var(&key_file, NO_SUCH_KEY_FILE);
        EnvGuard { saved }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        let (name, _) = &self.saved[0];
        if let Some(current) = std::env::var_os(name) {
            std::env::set_var(name, "0".repeat(current.len()));
        }
        for (name, value) in &self.saved {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }
}

pub(crate) fn encrypt_yaml(plaintext: &str, recipient: &str) -> Result<String, BridgeError> {
    let _lock = rops_lock();
    reject_sops_key(plaintext)?;

    let key_id = AgeIntegration::parse_key_id(recipient).map_err(encrypt_error)?;
    let encrypted = RopsFileBuilder::<YamlFileFormat>::new(plaintext)
        .map_err(encrypt_error)?
        .add_integration_key::<AgeIntegration>(key_id)
        .encrypt::<AES256GCM, SHA512>()
        .map_err(encrypt_error)?;

    with_sops_version(&encrypted.to_string())
}

pub(crate) fn encrypt_yaml_to(
    plaintext: &str,
    recipients: &[String],
) -> Result<String, BridgeError> {
    let _lock = rops_lock();
    reject_sops_key(plaintext)?;

    if recipients.is_empty() {
        return Err(BridgeError::Encrypt("no recipients".to_string()));
    }
    let key_ids = recipients
        .iter()
        .map(|recipient| AgeIntegration::parse_key_id(recipient).map_err(encrypt_error))
        .collect::<Result<Vec<_>, _>>()?;
    let encrypted = RopsFileBuilder::<YamlFileFormat>::new(plaintext)
        .map_err(encrypt_error)?
        .add_integration_keys::<AgeIntegration>(key_ids)
        .encrypt::<AES256GCM, SHA512>()
        .map_err(encrypt_error)?;

    with_sops_version(&encrypted.to_string())
}

pub(crate) fn decrypt_yaml(
    ciphertext: &str,
    identity: &Identity,
) -> Result<serde_yaml::Mapping, BridgeError> {
    let _lock = rops_lock();
    let _env = EnvGuard::install(identity.expose());

    let encrypted = EncryptedYaml::from_str(ciphertext).map_err(decrypt_error)?;
    let decrypted: DecryptedYaml = encrypted
        .decrypt::<YamlFileFormat>()
        .map_err(decrypt_error)?;

    Ok(decrypted.into_inner_map())
}

pub(crate) fn update_recipients(
    ciphertext: &str,
    identity: &Identity,
    remove: &[String],
    add: &[String],
) -> Result<String, BridgeError> {
    let _lock = rops_lock();
    let _env = EnvGuard::install(identity.expose());
    let encrypted = EncryptedYaml::from_str(ciphertext).map_err(decrypt_error)?;
    let mut decrypted: DecryptedYaml = encrypted
        .decrypt::<YamlFileFormat>()
        .map_err(decrypt_error)?;
    let additions = add
        .iter()
        .map(|recipient| AgeIntegration::parse_key_id(recipient).map_err(encrypt_error))
        .collect::<Result<Vec<_>, _>>()?;
    decrypted
        .add_keys::<AgeIntegration>(additions)
        .map_err(encrypt_error)?;
    for recipient in remove {
        let key_id = AgeIntegration::parse_key_id(recipient).map_err(encrypt_error)?;
        decrypted
            .remove_integration_key::<AgeIntegration>(&key_id)
            .map_err(encrypt_error)?;
    }
    let encrypted = decrypted
        .encrypt::<AES256GCM, YamlFileFormat>()
        .map_err(encrypt_error)?;
    with_sops_version(&encrypted.to_string())
}

#[cfg(test)]
pub(crate) struct EnvSandbox {
    _guard: MutexGuard<'static, ()>,
}

#[cfg(test)]
impl EnvSandbox {
    pub(crate) fn acquire() -> Self {
        static TEST_LOCK: Mutex<()> = Mutex::new(());
        EnvSandbox {
            _guard: TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner()),
        }
    }

    pub(crate) fn set(&self, name: &str, value: impl AsRef<std::ffi::OsStr>) {
        std::env::set_var(name, value);
    }

    pub(crate) fn unset(&self, name: &str) {
        std::env::remove_var(name);
    }

    pub(crate) fn get(&self, name: &str) -> Option<OsString> {
        std::env::var_os(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;

    const PLAINTEXT: &str = "db:\n    password: hunter2\n";

    fn identity_pair() -> (String, Identity) {
        let key = age::x25519::Identity::generate();
        let recipient = key.to_public().to_string();
        let identity = Identity::from_secret_key(key.to_string().expose_secret()).unwrap();
        (recipient, identity)
    }

    #[test]
    fn emitted_metadata_carries_a_sops_version() {
        let env = EnvSandbox::acquire();
        let (recipient, identity) = identity_pair();
        let ciphertext = encrypt_yaml(PLAINTEXT, &recipient).unwrap();

        let parsed: serde_yaml::Value = serde_yaml::from_str(&ciphertext).unwrap();
        assert_eq!(
            parsed["sops"]["version"].as_str(),
            Some("3.8.1"),
            "{ciphertext}"
        );
        let recovered = decrypt_yaml(&ciphertext, &identity).unwrap();
        assert_eq!(
            recovered
                .get("db")
                .and_then(|db| db.get("password"))
                .and_then(|value| value.as_str()),
            Some("hunter2")
        );
        env.unset("ROPS_AGE");
        env.unset("ROPS_AGE_KEY_FILE");
    }

    #[test]
    fn a_top_level_sops_key_is_rejected_but_a_nested_one_is_not() {
        let env = EnvSandbox::acquire();
        let (recipient, identity) = identity_pair();

        let error = encrypt_yaml("sops:\n    evil: x\n", &recipient).unwrap_err();
        assert!(error.to_string().contains("collides"), "{error}");

        let error =
            encrypt_yaml_to("sops:\n    evil: x\n", std::slice::from_ref(&recipient)).unwrap_err();
        assert!(error.to_string().contains("collides"), "{error}");

        let nested = encrypt_yaml("db:\n    sops: allowed\n", &recipient).unwrap();
        decrypt_yaml(&nested, &identity).unwrap();

        env.unset("ROPS_AGE");
        env.unset("ROPS_AGE_KEY_FILE");
    }

    #[test]
    fn the_sops_binary_can_decrypt_our_output() {
        let env = EnvSandbox::acquire();
        let (recipient, identity) = identity_pair();
        let ciphertext = encrypt_yaml(PLAINTEXT, &recipient).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("secrets.dev.enc.yaml");
        let key = dir.path().join("identity.key");
        std::fs::write(&file, &ciphertext).unwrap();
        std::fs::write(&key, identity.expose()).unwrap();

        match std::process::Command::new("sops")
            .arg("--decrypt")
            .arg(&file)
            .env("SOPS_AGE_KEY_FILE", &key)
            .output()
        {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("skipped: the sops binary is unavailable: {error}")
            }
            Err(error) => panic!("cannot launch sops: {error}"),
            Ok(output) => {
                assert!(
                    output.status.success(),
                    "sops refused our file: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert!(String::from_utf8_lossy(&output.stdout).contains("hunter2"));
            }
        }

        env.unset("ROPS_AGE");
        env.unset("ROPS_AGE_KEY_FILE");
    }

    #[test]
    fn restores_both_rops_variables_exactly() {
        let env = EnvSandbox::acquire();
        let (recipient, identity) = identity_pair();
        let ciphertext = encrypt_yaml(PLAINTEXT, &recipient).unwrap();

        env.set("ROPS_AGE", "preset-identity");
        env.unset("ROPS_AGE_KEY_FILE");

        decrypt_yaml(&ciphertext, &identity).unwrap();

        assert_eq!(env.get("ROPS_AGE"), Some(OsString::from("preset-identity")));
        assert_eq!(env.get("ROPS_AGE_KEY_FILE"), None);

        env.set("ROPS_AGE_KEY_FILE", "/preset/rops/keys");

        decrypt_yaml(&ciphertext, &identity).unwrap();

        assert_eq!(env.get("ROPS_AGE"), Some(OsString::from("preset-identity")));
        assert_eq!(
            env.get("ROPS_AGE_KEY_FILE"),
            Some(OsString::from("/preset/rops/keys"))
        );

        env.unset("ROPS_AGE");
        env.unset("ROPS_AGE_KEY_FILE");
    }

    #[test]
    fn restores_both_rops_variables_after_a_panic() {
        let env = EnvSandbox::acquire();
        let key = AgeIntegration::private_key_env_var_name();
        let key_file = AgeIntegration::private_key_file_path_override_env_var_name();
        env.set(&key, "preset-identity");
        env.unset(&key_file);

        let result = std::panic::catch_unwind(|| {
            let _guard = EnvGuard::install("secret-identity");
            panic!("forced");
        });

        assert!(result.is_err());
        assert_eq!(env.get(&key), Some(OsString::from("preset-identity")));
        assert_eq!(env.get(&key_file), None);
    }

    #[test]
    fn never_consults_the_configured_key_file() {
        let env = EnvSandbox::acquire();
        let holder = age::x25519::Identity::generate();
        let stranger = age::x25519::Identity::generate();
        let ciphertext =
            encrypt_yaml(PLAINTEXT, &holder.to_public().to_string()).expect("encrypt to holder");

        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("age_keys");
        std::fs::write(&key_file, holder.to_string().expose_secret()).unwrap();
        env.set("ROPS_AGE_KEY_FILE", &key_file);

        let identity = Identity::from_secret_key(stranger.to_string().expose_secret()).unwrap();
        let result = decrypt_yaml(&ciphertext, &identity);

        env.unset("ROPS_AGE_KEY_FILE");

        assert!(
            result.is_err(),
            "the key file at ROPS_AGE_KEY_FILE was consulted"
        );
    }

    #[test]
    fn removing_a_recipient_rotates_before_new_keys_are_added() {
        let (alice_recipient, alice) = identity_pair();
        let (bob_recipient, bob) = identity_pair();
        let (carol_recipient, carol) = identity_pair();
        let first = encrypt_yaml(PLAINTEXT, &alice_recipient).unwrap();
        let shared =
            update_recipients(&first, &alice, &[], std::slice::from_ref(&bob_recipient)).unwrap();
        assert!(decrypt_yaml(&shared, &bob).is_ok());

        let rotated =
            update_recipients(&shared, &alice, &[bob_recipient], &[carol_recipient]).unwrap();
        assert!(decrypt_yaml(&rotated, &bob).is_err());
        assert!(decrypt_yaml(&rotated, &alice).is_ok());
        assert!(decrypt_yaml(&rotated, &carol).is_ok());
    }
}
