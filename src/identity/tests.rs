use super::*;
use crate::rops_bridge::EnvSandbox;
use age::secrecy::{ExposeSecret, SecretString};
use std::io::Write;

struct CountingPrompt {
    passphrase: String,
    calls: usize,
}

impl PassphrasePrompt for CountingPrompt {
    fn prompt(&mut self, tier: &str) -> Result<Zeroizing<String>, IdentityError> {
        self.calls += 1;
        if self.calls > 1 {
            return Err(IdentityError::Prompt {
                tier: tier.to_string(),
                source: std::io::Error::other("prompted twice"),
            });
        }
        Ok(Zeroizing::new(self.passphrase.clone()))
    }
}

fn counting(passphrase: &str) -> CountingPrompt {
    CountingPrompt {
        passphrase: passphrase.to_string(),
        calls: 0,
    }
}

fn generate_key() -> String {
    age::x25519::Identity::generate()
        .to_string()
        .expose_secret()
        .to_string()
}

fn passphrase_encrypt(payload: &[u8], passphrase: &str) -> Vec<u8> {
    let mut recipient = age::scrypt::Recipient::new(SecretString::from(passphrase.to_owned()));
    recipient.set_work_factor(10);
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .unwrap();
    let mut out = Vec::new();
    let mut writer = encryptor.wrap_output(&mut out).unwrap();
    writer.write_all(payload).unwrap();
    writer.finish().unwrap();
    out
}

fn home_at(dir: &Path) -> (EnvSandbox, PathBuf) {
    let env = EnvSandbox::acquire();
    env.unset(IDENTITY_ENV);
    env.set("XDG_CONFIG_HOME", dir);
    env.set("HOME", dir);
    let config = dir.join("yett");
    std::fs::create_dir_all(&config).unwrap();
    (env, config.join("dev.key.age"))
}

fn opt(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}

const PRECEDENCE: &[(&str, &str, &str, &str, &str, &str)] = &[
    ("dev", "/f/dev.key", "/e/dev.key", "/x", "/h", "/f/dev.key"),
    ("dev", "", "/e/dev.key", "/x", "/h", "/e/dev.key"),
    ("dev", "", "", "/x", "/h", "/x/yett/dev.key.age"),
    ("dev", "", "", "", "/h", "/h/.config/yett/dev.key.age"),
    ("prod", "", "", "", "/h", "/h/.config/yett/prod.key.age"),
    ("staging", "", "", "/x", "", "/x/yett/staging.key.age"),
];

#[test]
fn identity_path_precedence() {
    for (tier, explicit, env, xdg, home, want) in PRECEDENCE {
        let got = resolve_identity_path(
            tier,
            opt(explicit).map(Path::new),
            opt(env).map(OsStr::new),
            opt(xdg).map(Path::new),
            opt(home).map(Path::new),
        );
        assert_eq!(got, Path::new(want), "{tier} {explicit:?} {env:?}");
    }
}

const TIERS: &[(&str, Option<&str>)] = &[
    (".yett/secrets.dev.enc.yaml", Some("dev")),
    ("secrets.staging.enc.yaml", Some("staging")),
    ("/abs/secrets.prod.enc.yaml", Some("prod")),
    ("secrets..enc.yaml", None),
    ("secrets.enc.yaml", None),
    ("secrets.dev.enc.yml", None),
    ("secrets.dev.yaml", None),
    ("Secrets.dev.enc.yaml", None),
    ("other.dev.enc.yaml", None),
    ("secrets.dev.enc.yaml.bak", None),
    ("", None),
];

#[test]
fn tier_from_file_name() {
    for (input, want) in TIERS {
        assert_eq!(
            tier_from_secret_path(Path::new(input)).as_deref(),
            *want,
            "{input}"
        );
    }
}

#[test]
fn plaintext_keys_are_rejected_only_at_the_default_path() {
    let dir = tempfile::tempdir().unwrap();
    let (_env, default_path) = home_at(dir.path());
    let key = generate_key();
    std::fs::write(&default_path, &key).unwrap();

    let err = IdentityStore::new()
        .load("dev", None, &mut counting("unused"))
        .expect_err("a plaintext key at the default path must be rejected");
    assert!(
        matches!(err, IdentityError::PlaintextAtDefaultPath(_)),
        "got {err:?}"
    );

    let explicit = dir.path().join("ci.key");
    std::fs::write(&explicit, &key).unwrap();
    let identity = IdentityStore::new()
        .load("dev", Some(&explicit), &mut counting("unused"))
        .expect("an explicit plaintext key is the CI case");
    assert_eq!(identity.expose(), key.trim());
}

#[test]
fn encrypted_identity_needs_the_right_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    let (_env, default_path) = home_at(dir.path());
    let key = generate_key();
    std::fs::write(
        &default_path,
        passphrase_encrypt(key.as_bytes(), "correct horse"),
    )
    .unwrap();

    let identity = IdentityStore::new()
        .load("dev", None, &mut counting("correct horse"))
        .expect("the correct passphrase must decrypt");
    assert_eq!(identity.expose(), key.trim());

    let err = IdentityStore::new()
        .load("dev", None, &mut counting("wrong horse"))
        .expect_err("the wrong passphrase must fail");
    assert!(matches!(err, IdentityError::Decrypt { .. }), "got {err:?}");
}

#[test]
fn a_tier_is_prompted_for_exactly_once() {
    let dir = tempfile::tempdir().unwrap();
    let (_env, default_path) = home_at(dir.path());
    std::fs::write(
        &default_path,
        passphrase_encrypt(generate_key().as_bytes(), "open sesame"),
    )
    .unwrap();

    let store = IdentityStore::new();
    let mut prompt = counting("open sesame");
    let first = store.load("dev", None, &mut prompt).unwrap();
    let second = store.load("dev", None, &mut prompt).unwrap();

    assert_eq!(prompt.calls, 1);
    assert_eq!(first.expose(), second.expose());
}
