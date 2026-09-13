use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::error::Error;
use crate::harden::ResolvedSecret;
use crate::identity::{self, IdentityStore, PassphrasePrompt, TtyPrompt};
use crate::r#ref::Ref;
use crate::sops::SecretDocument;

pub struct Resolver {
    identities: IdentityStore,
    explicit: Option<PathBuf>,
    documents: Mutex<HashMap<PathBuf, Arc<SecretDocument>>>,
    prompt: Mutex<Box<dyn PassphrasePrompt + Send>>,
}

impl Default for Resolver {
    fn default() -> Self {
        Self::with_identity(None)
    }
}

impl Resolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_identity(explicit: Option<PathBuf>) -> Self {
        Resolver {
            identities: IdentityStore::new(),
            explicit,
            documents: Mutex::new(HashMap::new()),
            prompt: Mutex::new(Box::new(TtyPrompt)),
        }
    }

    pub fn resolve(&self, r: &Ref) -> Result<ResolvedSecret, Error> {
        r.ensure_supported()?;

        let path = PathBuf::from(r.path());
        let tier = identity::tier_from_secret_path(&path).ok_or_else(|| {
            Error::Usage(format!(
                "cannot tell the tier from {}; expected a secrets.<tier>.enc.yaml file name",
                path.display()
            ))
        })?;

        let document = self.document(&path, &tier)?;
        Ok(document.resolve_pointer(&r.pointer()?)?)
    }

    pub fn resolve_env(
        &self,
        env: &BTreeMap<String, String>,
    ) -> Result<BTreeMap<String, ResolvedSecret>, Error> {
        let mut resolved = BTreeMap::new();
        for (name, value) in env {
            let secret = match Ref::is_ref(value) {
                true => self.resolve(&Ref::parse(value)?)?,
                false => ResolvedSecret::new(value.clone()),
            };
            resolved.insert(name.clone(), secret);
        }
        Ok(resolved)
    }

    fn document(&self, path: &Path, tier: &str) -> Result<Arc<SecretDocument>, Error> {
        if let Some(cached) = self.cached(path) {
            return Ok(cached);
        }

        let identity = {
            let mut prompt = self.prompt.lock().unwrap_or_else(|e| e.into_inner());
            self.identities
                .load(tier, self.explicit.as_deref(), prompt.as_mut())?
        };
        let document = Arc::new(SecretDocument::load(path, &identity)?);

        let mut documents = self.documents.lock().unwrap_or_else(|e| e.into_inner());
        Ok(Arc::clone(
            documents.entry(path.to_path_buf()).or_insert(document),
        ))
    }

    fn cached(&self, path: &Path) -> Option<Arc<SecretDocument>> {
        let documents = self.documents.lock().unwrap_or_else(|e| e.into_inner());
        documents.get(path).map(Arc::clone)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IDENTITY_ENV;
    use crate::rops_bridge::EnvSandbox;
    use crate::sops::encrypt_yaml;
    use secrecy::ExposeSecret;
    use std::path::Path;

    const DOC: &str = concat!(
        "db:\n",
        "    password: hunter2\n",
        "stripe:\n",
        "    api_key: sk_live_42\n",
    );

    struct Fixture {
        env: EnvSandbox,
        dir: tempfile::TempDir,
        key: PathBuf,
        secrets: PathBuf,
    }

    fn fixture() -> Fixture {
        let env = EnvSandbox::acquire();
        env.unset(IDENTITY_ENV);

        let dir = tempfile::tempdir().unwrap();
        let key = age::x25519::Identity::generate();
        let key_path = dir.path().join("dev.key");
        std::fs::write(&key_path, key.to_string().expose_secret()).unwrap();

        let secrets = dir.path().join("secrets.dev.enc.yaml");
        let ciphertext = encrypt_yaml(DOC, &key.to_public().to_string()).unwrap();
        std::fs::write(&secrets, ciphertext).unwrap();

        Fixture {
            env,
            dir,
            key: key_path,
            secrets,
        }
    }

    impl Fixture {
        fn resolver(&self) -> Resolver {
            Resolver::with_identity(Some(self.key.clone()))
        }

        fn reference(&self, fragment: &str) -> Ref {
            Ref::parse(&format!("ref+sops://{}{fragment}", self.secrets.display())).unwrap()
        }
    }

    #[test]
    fn resolves_a_pointer_into_a_secret_string() {
        let f = fixture();
        let value = f.resolver().resolve(&f.reference("#/db/password")).unwrap();
        assert_eq!(value.expose_secret(), "hunter2");
    }

    #[test]
    fn a_cached_document_outlives_the_file() {
        let f = fixture();
        let resolver = f.resolver();

        let first = resolver.resolve(&f.reference("#/db/password")).unwrap();
        assert_eq!(first.expose_secret(), "hunter2");

        std::fs::remove_file(&f.secrets).unwrap();
        assert!(!f.secrets.exists());

        let second = resolver.resolve(&f.reference("#/stripe/api_key")).unwrap();
        assert_eq!(second.expose_secret(), "sk_live_42");
    }

    #[test]
    fn a_missing_pointer_is_unresolved() {
        let f = fixture();
        let err = f
            .resolver()
            .resolve(&f.reference("#/db/nope"))
            .expect_err("a missing pointer must fail");
        assert!(matches!(err, Error::Unresolved(_)), "{err:?}");
        assert_eq!(err.exit_code(), 3);
    }

    #[test]
    fn a_foreign_identity_is_a_decryption_failure() {
        let f = fixture();
        let stranger = age::x25519::Identity::generate();
        let stranger_path = f.dir.path().join("stranger.key");
        std::fs::write(&stranger_path, stranger.to_string().expose_secret()).unwrap();

        let err = Resolver::with_identity(Some(stranger_path))
            .resolve(&f.reference("#/db/password"))
            .expect_err("a foreign identity must fail");
        assert!(matches!(err, Error::Decryption(_)), "{err:?}");
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn a_reserved_backend_is_a_usage_error() {
        let f = fixture();
        let err = f
            .resolver()
            .resolve(&Ref::parse("ref+vault://secret/data/app#/key").unwrap())
            .expect_err("vault is not implemented");
        assert!(matches!(err, Error::Usage(_)), "{err:?}");
        assert_eq!(err.to_string(), "backend not implemented");
    }

    #[test]
    fn a_path_without_a_tier_is_a_usage_error() {
        let f = fixture();
        let stray = f.dir.path().join("secrets.yaml");
        std::fs::copy(&f.secrets, &stray).unwrap();

        let err = f
            .resolver()
            .resolve(&Ref::parse(&format!("ref+sops://{}#/db/password", stray.display())).unwrap())
            .expect_err("a file name without a tier must fail");
        assert!(matches!(err, Error::Usage(_)), "{err:?}");
        assert_eq!(err.exit_code(), 1);
        assert!(err.to_string().contains("secrets.yaml"), "{err}");
    }

    #[test]
    fn resolve_env_mixes_literals_and_references() {
        let f = fixture();
        let reference = format!("ref+sops://{}#/db/password", f.secrets.display());
        let env = BTreeMap::from([
            ("DATABASE_PASSWORD".to_string(), reference),
            ("LOG_LEVEL".to_string(), "debug".to_string()),
            ("EMPTY".to_string(), String::new()),
        ]);

        let resolved = f.resolver().resolve_env(&env).unwrap();

        assert_eq!(resolved.len(), 3);
        assert_eq!(resolved["DATABASE_PASSWORD"].expose_secret(), "hunter2");
        assert_eq!(resolved["LOG_LEVEL"].expose_secret(), "debug");
        assert_eq!(resolved["EMPTY"].expose_secret(), "");
    }

    #[test]
    fn resolve_env_never_passes_a_reference_through() {
        let f = fixture();
        let broken = format!("ref+sops://{}#/db/nope", f.secrets.display());
        let env = BTreeMap::from([
            ("LOG_LEVEL".to_string(), "debug".to_string()),
            ("BROKEN".to_string(), broken),
        ]);

        let err = f
            .resolver()
            .resolve_env(&env)
            .expect_err("an unresolvable reference must fail the whole map");
        assert_eq!(err.exit_code(), 3);

        let malformed = BTreeMap::from([("BAD".to_string(), "ref+nonsense".to_string())]);
        let err = f
            .resolver()
            .resolve_env(&malformed)
            .expect_err("a malformed reference must fail");
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn the_explicit_identity_wins_over_the_environment() {
        let f = fixture();
        f.env
            .set(IDENTITY_ENV, Path::new("/nonexistent/yett/env.key"));

        let value = f.resolver().resolve(&f.reference("#/db/password")).unwrap();

        f.env.unset(IDENTITY_ENV);
        assert_eq!(value.expose_secret(), "hunter2");
    }

    #[test]
    fn the_resolved_value_is_a_locked_secret_type() {
        let f = fixture();
        let value = f.resolver().resolve(&f.reference("#/db/password")).unwrap();

        assert_eq!(value.expose_secret(), "hunter2");
        assert_eq!(value.len(), 7);
        assert!(!value.is_empty());
        assert_eq!(format!("{value:?}"), "ResolvedSecret(<redacted>)");
    }

    #[test]
    fn resolve_env_wraps_a_literal_in_the_same_locked_type() {
        let f = fixture();
        let env = BTreeMap::from([("EMPTY".to_string(), String::new())]);

        let resolved = f.resolver().resolve_env(&env).unwrap();

        assert!(resolved["EMPTY"].is_empty());
        assert_eq!(resolved["EMPTY"].len(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_held_resolved_secret_shows_up_in_vmlck() {
        use crate::harden::page_size;
        use crate::sops::encrypt_yaml;

        let env = EnvSandbox::acquire();
        env.unset(IDENTITY_ENV);
        let dir = tempfile::tempdir().unwrap();
        let key = age::x25519::Identity::generate();
        let key_path = dir.path().join("dev.key");
        std::fs::write(&key_path, key.to_string().expose_secret()).unwrap();
        let big = "z".repeat(128 * 1024);
        let doc = format!("db:\n    password: hunter2\nbig:\n    blob: {big}\n");
        let secrets = dir.path().join("secrets.dev.enc.yaml");
        std::fs::write(
            &secrets,
            encrypt_yaml(&doc, &key.to_public().to_string()).unwrap(),
        )
        .unwrap();

        let resolver = Resolver::with_identity(Some(key_path));
        let warm = format!("ref+sops://{}#/db/password", secrets.display());
        let _warm = resolver.resolve(&Ref::parse(&warm).unwrap()).unwrap();

        let baseline = vmlck_bytes().expect("VmLck must be readable");

        let reference = Ref::parse(&format!("ref+sops://{}#/big/blob", secrets.display())).unwrap();
        let secret = resolver.resolve(&reference).unwrap();
        assert_eq!(secret.len(), 128 * 1024);
        let locked = vmlck_bytes().expect("VmLck must be readable");
        assert!(
            locked >= baseline + 64 * 1024,
            "baseline={baseline} locked={locked}"
        );

        drop(secret);
        let after = vmlck_bytes().expect("VmLck must be readable");
        assert!(
            after <= baseline + page_size(),
            "baseline={baseline} after={after}"
        );
    }

    #[cfg(target_os = "linux")]
    fn vmlck_bytes() -> Option<usize> {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        let line = status.lines().find(|line| line.starts_with("VmLck:"))?;
        let kb: usize = line.split_whitespace().nth(1)?.parse().ok()?;
        Some(kb * 1024)
    }
}
