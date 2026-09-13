use std::os::unix::fs::PermissionsExt;

use super::*;
use crate::identity::{IdentityError, IdentityStore, Passphrase};
use crate::rops_bridge::EnvSandbox;

struct FakePrompt {
    passphrase: String,
    confirmation: String,
    prompts: usize,
    confirms: usize,
}

impl FakePrompt {
    fn matching(passphrase: &str) -> Self {
        Self {
            passphrase: passphrase.to_string(),
            confirmation: passphrase.to_string(),
            prompts: 0,
            confirms: 0,
        }
    }

    fn mismatched(passphrase: &str, confirmation: &str) -> Self {
        Self {
            passphrase: passphrase.to_string(),
            confirmation: confirmation.to_string(),
            prompts: 0,
            confirms: 0,
        }
    }
}

impl PassphrasePrompt for FakePrompt {
    fn prompt(&mut self, _tier: &str) -> Result<Passphrase, IdentityError> {
        self.prompts += 1;
        Ok(Zeroizing::new(self.passphrase.clone()))
    }

    fn confirm(&mut self, _tier: &str) -> Result<Passphrase, IdentityError> {
        self.confirms += 1;
        Ok(Zeroizing::new(self.confirmation.clone()))
    }
}

fn config_home(dir: &Path) -> (EnvSandbox, PathBuf) {
    let env = EnvSandbox::acquire();
    env.unset("YETT_IDENTITY");
    env.set("XDG_CONFIG_HOME", dir);
    env.set("HOME", dir);
    (env, dir.join("yett").join("dev.key.age"))
}

#[test]
fn parse_tiers_accepts_a_comma_separated_list() {
    assert_eq!(parse_tiers("dev").unwrap(), vec!["dev".to_string()]);
    assert_eq!(
        parse_tiers("dev,staging,prod").unwrap(),
        vec!["dev".to_string(), "staging".to_string(), "prod".to_string()]
    );
    assert_eq!(
        parse_tiers("dev, staging").unwrap(),
        vec!["dev".to_string(), "staging".to_string()]
    );
    assert_eq!(
        parse_tiers("build-1,ci_2").unwrap(),
        vec!["build-1".to_string(), "ci_2".to_string()]
    );
}

#[test]
fn parse_tiers_rejects_empty_duplicate_and_invalid_names() {
    for spec in ["", "dev,", ",dev", "dev,,prod"] {
        assert!(parse_tiers(spec).is_err(), "{spec}");
    }
    assert!(parse_tiers("dev,dev").is_err());
    for spec in ["de/v", "de v", "dév"] {
        assert!(parse_tiers(spec).is_err(), "{spec}");
    }
}

#[test]
fn keygen_writes_a_passphrase_encrypted_identity_at_the_default_path() {
    let dir = tempfile::tempdir().unwrap();
    let (_env, expected_path) = config_home(dir.path());

    let mut prompt = FakePrompt::matching("correct horse battery");
    let out = keygen("dev", &mut prompt, Some(10)).unwrap();

    assert_eq!(out.tier, "dev");
    assert_eq!(out.path, expected_path);
    assert_eq!(prompt.prompts, 1);
    assert_eq!(prompt.confirms, 1);
    assert!(out.public_key.starts_with("age1"), "{}", out.public_key);
    assert_eq!(out.yaml_line, format!("      dev: {}", out.public_key));

    let bytes = std::fs::read(&out.path).unwrap();
    assert!(bytes.starts_with(b"age-encryption.org/v1"), "not age");
    assert!(
        !bytes.windows(16).any(|w| w == b"AGE-SECRET-KEY-1"),
        "the private key leaked in plaintext"
    );
    let mode = std::fs::metadata(&out.path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    let identity = IdentityStore::new()
        .load(
            "dev",
            None,
            &mut FakePrompt::matching("correct horse battery"),
        )
        .expect("the identity must decrypt with the same passphrase");
    assert_eq!(identity.recipient(), out.public_key);
}

#[test]
fn keygen_refuses_to_overwrite_an_existing_identity() {
    let dir = tempfile::tempdir().unwrap();
    let (_env, path) = config_home(dir.path());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"leave me alone").unwrap();

    let err = keygen("dev", &mut FakePrompt::matching("pw"), Some(10))
        .expect_err("an existing identity must be refused");
    assert!(matches!(err, Error::Usage(_)), "{err:?}");
    assert_eq!(std::fs::read(&path).unwrap(), b"leave me alone");
}

#[test]
fn keygen_rejects_an_empty_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    let (_env, path) = config_home(dir.path());

    let mut prompt = FakePrompt::matching("");
    let err = keygen("dev", &mut prompt, Some(10)).expect_err("empty must fail");
    assert!(matches!(err, Error::Usage(_)), "{err:?}");
    assert!(!path.exists());
}

#[test]
fn keygen_rejects_mismatched_passphrases() {
    let dir = tempfile::tempdir().unwrap();
    let (_env, path) = config_home(dir.path());

    let mut prompt = FakePrompt::mismatched("first", "second");
    let err = keygen("dev", &mut prompt, Some(10)).expect_err("mismatch must fail");
    assert!(matches!(err, Error::Usage(_)), "{err:?}");
    assert!(!path.exists());
}

#[test]
fn keygen_ignores_environment_passphrase_channels() {
    let dir = tempfile::tempdir().unwrap();
    let (env, _path) = config_home(dir.path());
    env.set("YETT_PASSPHRASE", "from-the-environment");

    let mut prompt = FakePrompt::matching("from-the-tty");
    keygen("dev", &mut prompt, Some(10)).unwrap();

    assert_eq!(prompt.prompts, 1);
    assert_eq!(prompt.confirms, 1);
}

#[test]
fn keygen_fails_when_no_config_or_home_is_set() {
    let env = EnvSandbox::acquire();
    env.unset("YETT_IDENTITY");
    env.unset("XDG_CONFIG_HOME");
    env.unset("HOME");

    let err = keygen("dev", &mut FakePrompt::matching("pw"), Some(10))
        .expect_err("no path is determinable");
    assert!(matches!(err, Error::Usage(_)), "{err:?}");
    assert!(err.to_string().contains("cannot determine"));
}

fn scaffold_access(root: &Path) {
    std::fs::create_dir_all(root.join(".yett")).unwrap();
    std::fs::write(
        root.join(".yett/secrets-access.yaml"),
        "version: 1\npeople: []\n",
    )
    .unwrap();
}

#[test]
fn keygen_register_creates_the_identity_and_registers_it() {
    let dir = tempfile::tempdir().unwrap();
    let (_env, expected_path) = config_home(dir.path());
    scaffold_access(dir.path());

    let mut prompt = FakePrompt::matching("correct horse battery");
    let out = keygen_register("dev", "you", dir.path(), &mut prompt, Some(10)).unwrap();

    assert_eq!(out.tier, "dev");
    assert_eq!(out.handle, "you");
    assert_eq!(out.path, expected_path);
    assert!(!out.reused);
    assert!(out.public_key.starts_with("age1"), "{}", out.public_key);
    assert!(out.path.is_file());

    let access = AccessList::load(&dir.path().join(".yett/secrets-access.yaml")).unwrap();
    assert_eq!(access.recipients("dev").len(), 1);
    assert_eq!(access.recipients("dev")[0].to_string(), out.public_key);

    let sops = std::fs::read_to_string(dir.path().join(".sops.yaml")).unwrap();
    assert_eq!(sops, access.render_sops_config());
    assert!(sops.contains(&out.public_key), "{sops}");

    let identity = IdentityStore::new()
        .load(
            "dev",
            None,
            &mut FakePrompt::matching("correct horse battery"),
        )
        .expect("the identity must decrypt with the same passphrase");
    assert_eq!(identity.recipient(), out.public_key);
}

#[test]
fn keygen_register_reuses_an_existing_identity_with_one_prompt() {
    let dir = tempfile::tempdir().unwrap();
    let (_env, _path) = config_home(dir.path());
    scaffold_access(dir.path());

    let first = keygen_register(
        "dev",
        "you",
        dir.path(),
        &mut FakePrompt::matching("pw"),
        Some(10),
    )
    .unwrap();
    let bytes_before = std::fs::read(&first.path).unwrap();

    let mut prompt = FakePrompt::matching("pw");
    let second = keygen_register("dev", "you", dir.path(), &mut prompt, Some(10)).unwrap();

    assert!(second.reused, "{second:?}");
    assert_eq!(prompt.prompts, 1);
    assert_eq!(prompt.confirms, 0);
    assert_eq!(second.public_key, first.public_key);
    assert_eq!(std::fs::read(&second.path).unwrap(), bytes_before);

    let access = AccessList::load(&dir.path().join(".yett/secrets-access.yaml")).unwrap();
    let keys = access.recipients("dev");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].to_string(), first.public_key);
}

#[test]
fn keygen_register_without_an_access_list_names_init_and_writes_no_identity() {
    let dir = tempfile::tempdir().unwrap();
    let (_env, path) = config_home(dir.path());

    let mut prompt = FakePrompt::matching("pw");
    let error = keygen_register("dev", "you", dir.path(), &mut prompt, Some(10))
        .expect_err("no access list");
    assert!(matches!(error, Error::Usage(_)), "{error:?}");
    assert!(error.to_string().contains("yett init"), "{error}");
    assert!(!path.exists());
    assert_eq!(prompt.prompts, 0);
    assert!(!dir.path().join(".sops.yaml").exists());
}

#[test]
fn init_with_handle_scaffolds_and_registers_in_one_step() {
    let dir = tempfile::tempdir().unwrap();
    let (_env, path) = config_home(dir.path());

    let mut prompt = FakePrompt::matching("pw");
    let out = init_with_handle_impl(dir.path(), "dev", "you", &mut prompt, Some(10), true).unwrap();

    assert!(out.init.access_path.is_file());
    assert!(out.init.sops_path.is_file());
    assert!(path.is_file());
    assert_eq!(prompt.prompts, 1);
    assert_eq!(prompt.confirms, 1);

    let access = AccessList::load(&out.init.access_path).unwrap();
    assert_eq!(access.recipients("dev").len(), 1);
    assert_eq!(
        access.recipients("dev")[0].to_string(),
        out.register.public_key
    );
    let sops = std::fs::read_to_string(&out.init.sops_path).unwrap();
    assert!(sops.contains(&out.register.public_key), "{sops}");
}

#[test]
fn init_with_handle_refuses_more_than_one_tier_without_writing() {
    let dir = tempfile::tempdir().unwrap();
    let (_env, _path) = config_home(dir.path());

    let error = init_with_handle_impl(
        dir.path(),
        "dev,staging",
        "you",
        &mut FakePrompt::matching("pw"),
        Some(10),
        true,
    )
    .expect_err("more than one tier must be refused");
    assert!(matches!(error, Error::Usage(_)), "{error:?}");
    let text = error.to_string();
    assert!(text.contains("dev"), "{text}");
    assert!(text.contains("staging"), "{text}");
    assert!(text.contains("keygen --register"), "{text}");
    assert!(!dir.path().join(".yett").exists());
    assert!(!dir.path().join(".sops.yaml").exists());
}

#[test]
fn init_with_handle_refuses_without_a_tty_without_writing() {
    let dir = tempfile::tempdir().unwrap();
    let (_env, _path) = config_home(dir.path());

    let error = init_with_handle_impl(
        dir.path(),
        "dev",
        "you",
        &mut FakePrompt::matching("pw"),
        Some(10),
        false,
    )
    .expect_err("a non-tty must be refused");
    assert!(matches!(error, Error::Usage(_)), "{error:?}");
    let text = error.to_string();
    assert!(text.contains("yett init"), "{text}");
    assert!(text.contains("yett keygen"), "{text}");
    assert!(!dir.path().join(".yett").exists());
}

#[test]
fn init_scaffolds_and_refuses_a_second_run() {
    let dir = tempfile::tempdir().unwrap();
    let tiers = parse_tiers("dev,staging").unwrap();

    let out = init(dir.path(), &tiers).unwrap();
    assert_eq!(out.tiers, tiers);
    assert!(out.access_path.is_file());
    assert!(out.sops_path.is_file());
    assert!(out.env_refs_path.is_file());

    let sops_before = std::fs::read_to_string(&out.sops_path).unwrap();
    let access = AccessList::load(&out.access_path).unwrap();
    assert_eq!(sops_before, access.render_sops_config());
    assert_eq!(
        sops_before,
        "# generated by yett — edit secrets-access.yaml instead\ncreation_rules:\n"
    );

    let err = init(dir.path(), &tiers).expect_err("a second init must refuse");
    assert!(matches!(err, Error::Usage(_)), "{err:?}");
    assert_eq!(
        std::fs::read_to_string(&out.sops_path).unwrap(),
        sops_before
    );
}

#[test]
fn init_rolls_back_what_it_created_when_a_later_artifact_exists() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".sops.yaml"), "occupied\n").unwrap();

    let error = init(dir.path(), &["dev".to_string()]).expect_err("occupied config");
    assert!(error.to_string().contains("already exists"), "{error}");

    assert!(!dir.path().join(".yett/secrets-access.yaml").exists());
    assert!(!dir.path().join(".env.refs").exists());
    assert!(!dir.path().join(".yett").exists());
    assert_eq!(
        std::fs::read_to_string(dir.path().join(".sops.yaml")).unwrap(),
        "occupied\n"
    );
}

#[test]
fn init_refuses_an_existing_env_refs() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".env.refs"), "KEEP=1\n").unwrap();

    let error = init(dir.path(), &["dev".to_string()]).expect_err("occupied env refs");
    assert!(error.to_string().contains("already exists"), "{error}");
    assert_eq!(
        std::fs::read_to_string(dir.path().join(".env.refs")).unwrap(),
        "KEEP=1\n"
    );
    assert!(!dir.path().join(".sops.yaml").exists());
}
