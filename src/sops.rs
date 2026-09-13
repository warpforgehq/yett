use std::path::{Path, PathBuf};

use zeroize::Zeroize;

use crate::harden::{PageLocks, ResolvedSecret};
use crate::identity::Identity;
use crate::rops_bridge::{self, BridgeError};

pub fn encrypt_yaml(plaintext: &str, recipient: &str) -> Result<String, BridgeError> {
    rops_bridge::encrypt_yaml(plaintext, recipient)
}

pub fn decrypt_yaml(
    ciphertext: &str,
    identity: &Identity,
) -> Result<serde_yaml::Mapping, BridgeError> {
    rops_bridge::decrypt_yaml(ciphertext, identity)
}

#[derive(Debug, thiserror::Error)]
pub enum SopsError {
    #[error("cannot read {}: {source}", path.display())]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{0}")]
    Decrypt(#[from] BridgeError),
    #[error("{}: no value at {pointer}", path.display())]
    MissingKey { path: PathBuf, pointer: String },
    #[error("{}: value at {pointer} is not a scalar", path.display())]
    NotAScalar { path: PathBuf, pointer: String },
}

pub struct SecretDocument {
    path: PathBuf,
    map: serde_yaml::Mapping,
    locks: PageLocks,
}

impl std::fmt::Debug for SecretDocument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretDocument({}, <redacted>)", self.path.display())
    }
}

impl SecretDocument {
    pub fn load(path: &Path, identity: &Identity) -> Result<Self, SopsError> {
        let ciphertext = std::fs::read_to_string(path).map_err(|source| SopsError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let map = rops_bridge::decrypt_yaml(&ciphertext, identity)?;
        let locks = PageLocks::for_mapping(&map);
        Ok(SecretDocument {
            path: path.to_path_buf(),
            map,
            locks,
        })
    }

    pub fn resolve_pointer(&self, segments: &[String]) -> Result<ResolvedSecret, SopsError> {
        let mut current: Option<&serde_yaml::Value> = None;
        for (depth, segment) in segments.iter().enumerate() {
            let map = match current {
                None => &self.map,
                Some(serde_yaml::Value::Mapping(map)) => map,
                Some(_) => return Err(self.missing_key(&segments[..=depth])),
            };
            current = Some(
                map.get(segment.as_str())
                    .ok_or_else(|| self.missing_key(&segments[..=depth]))?,
            );
        }

        match current {
            None => Err(self.not_a_scalar(segments)),
            Some(value) => Ok(ResolvedSecret::new(self.scalar_text(value, segments)?)),
        }
    }

    fn scalar_text(
        &self,
        value: &serde_yaml::Value,
        segments: &[String],
    ) -> Result<String, SopsError> {
        match value {
            serde_yaml::Value::String(text) => Ok(text.clone()),
            serde_yaml::Value::Number(number) => Ok(number.to_string()),
            serde_yaml::Value::Bool(flag) => Ok(flag.to_string()),
            serde_yaml::Value::Tagged(tagged) => self.scalar_text(&tagged.value, segments),
            _ => Err(self.not_a_scalar(segments)),
        }
    }

    fn missing_key(&self, segments: &[String]) -> SopsError {
        SopsError::MissingKey {
            path: self.path.clone(),
            pointer: pointer_text(segments),
        }
    }

    fn not_a_scalar(&self, segments: &[String]) -> SopsError {
        SopsError::NotAScalar {
            path: self.path.clone(),
            pointer: pointer_text(segments),
        }
    }
}

impl Drop for SecretDocument {
    fn drop(&mut self) {
        let _wiped = zeroize_mapping(&mut self.map);
        self.locks.release();
    }
}

fn pointer_text(segments: &[String]) -> String {
    if segments.is_empty() {
        return "/".to_string();
    }
    segments.iter().map(|s| format!("/{s}")).collect()
}

pub(crate) fn zeroize_mapping(map: &mut serde_yaml::Mapping) -> Vec<String> {
    let mut strings = Vec::new();
    take_strings(
        serde_yaml::Value::Mapping(std::mem::take(map)),
        &mut strings,
    );
    for text in &mut strings {
        text.zeroize();
    }
    strings
}

fn take_strings(value: serde_yaml::Value, out: &mut Vec<String>) {
    match value {
        serde_yaml::Value::String(text) => out.push(text),
        serde_yaml::Value::Sequence(items) => {
            for item in items {
                take_strings(item, out);
            }
        }
        serde_yaml::Value::Mapping(map) => {
            for (key, value) in map {
                take_strings(key, out);
                take_strings(value, out);
            }
        }
        serde_yaml::Value::Tagged(tagged) => take_strings(tagged.value, out),
        serde_yaml::Value::Null | serde_yaml::Value::Bool(_) | serde_yaml::Value::Number(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r#ref::Ref;
    use crate::rops_bridge::EnvSandbox;
    use secrecy::ExposeSecret;
    use serde_yaml::value::{Tag, TaggedValue};
    use serde_yaml::{Mapping, Value};

    const PLAINTEXT: &str = "db:\n    password: hunter2\n";

    const DOC: &str = concat!(
        "db:\n",
        "    password: hunter2\n",
        "    port: 5432\n",
        "    tls: true\n",
        "nested:\n",
        "    inner:\n",
        "        leaf: deep\n",
        "weird:\n",
        "    a/b: slash\n",
        "    a~b: tilde\n",
        "hosts:\n",
        "    - one\n",
        "blank:\n",
    );

    fn key_pair() -> (String, Identity) {
        let key = age::x25519::Identity::generate();
        let recipient = key.to_public().to_string();
        let identity = Identity::from_secret_key(key.to_string().expose_secret()).unwrap();
        (recipient, identity)
    }

    fn encrypted_document(dir: &Path, plaintext: &str) -> (PathBuf, Identity) {
        let (recipient, identity) = key_pair();
        let path = dir.join("secrets.dev.enc.yaml");
        std::fs::write(&path, encrypt_yaml(plaintext, &recipient).unwrap()).unwrap();
        (path, identity)
    }

    fn segments(reference: &str) -> Vec<String> {
        Ref::parse(reference).unwrap().pointer().unwrap()
    }

    #[test]
    fn age_yaml_round_trip_stays_in_memory() {
        let _env = EnvSandbox::acquire();

        let key = age::x25519::Identity::generate();
        let recipient = key.to_public().to_string();
        let identity = Identity::from_secret_key(key.to_string().expose_secret()).unwrap();

        let ciphertext = encrypt_yaml(PLAINTEXT, &recipient).unwrap();

        assert!(ciphertext.contains("ENC["));
        assert!(ciphertext.contains("sops:"));
        assert!(!ciphertext.contains("hunter2"));

        let recovered = decrypt_yaml(&ciphertext, &identity).unwrap();
        let password = recovered
            .get("db")
            .and_then(|db| db.get("password"))
            .and_then(|value| value.as_str());

        assert_eq!(Some("hunter2"), password);
    }

    const RESOLVED: &[(&str, &str)] = &[
        ("#/db/password", "hunter2"),
        ("#/nested/inner/leaf", "deep"),
        ("#/db/port", "5432"),
        ("#/db/tls", "true"),
        ("#/weird/a~1b", "slash"),
        ("#/weird/a~0b", "tilde"),
    ];

    #[test]
    fn resolves_nested_and_escaped_pointers() {
        let _env = EnvSandbox::acquire();
        let dir = tempfile::tempdir().unwrap();
        let (path, identity) = encrypted_document(dir.path(), DOC);

        let document = SecretDocument::load(&path, &identity).expect("the document must decrypt");

        for (fragment, want) in RESOLVED {
            let pointer = segments(&format!("ref+sops://{}{fragment}", path.display()));
            let value = document
                .resolve_pointer(&pointer)
                .unwrap_or_else(|e| panic!("{fragment}: {e}"));
            assert_eq!(value.expose_secret(), *want, "{fragment}");
        }
    }

    const MISSING: &[&str] = &[
        "#/db/nope",
        "#/nope/password",
        "#/db/password/deeper",
        "#/hosts/0",
    ];

    const NOT_SCALAR: &[&str] = &["#/db", "#/hosts", "#/blank", "#"];

    #[test]
    fn unresolvable_pointers_carry_their_kind() {
        let _env = EnvSandbox::acquire();
        let dir = tempfile::tempdir().unwrap();
        let (path, identity) = encrypted_document(dir.path(), DOC);
        let document = SecretDocument::load(&path, &identity).expect("the document must decrypt");

        for fragment in MISSING {
            let pointer = segments(&format!("ref+sops://{}{fragment}", path.display()));
            let err = document.resolve_pointer(&pointer).expect_err(fragment);
            assert!(
                matches!(err, SopsError::MissingKey { .. }),
                "{fragment}: got {err:?}"
            );
        }

        for fragment in NOT_SCALAR {
            let pointer = segments(&format!("ref+sops://{}{fragment}", path.display()));
            let err = document.resolve_pointer(&pointer).expect_err(fragment);
            assert!(
                matches!(err, SopsError::NotAScalar { .. }),
                "{fragment}: got {err:?}"
            );
        }
    }

    #[test]
    fn an_unreadable_file_and_a_foreign_identity_are_distinct_errors() {
        let _env = EnvSandbox::acquire();
        let dir = tempfile::tempdir().unwrap();
        let (path, _identity) = encrypted_document(dir.path(), DOC);
        let (_, stranger) = key_pair();

        let err = SecretDocument::load(&dir.path().join("secrets.prod.enc.yaml"), &stranger)
            .expect_err("a missing file must not decrypt");
        assert!(matches!(err, SopsError::Read { .. }), "got {err:?}");

        let err = SecretDocument::load(&path, &stranger)
            .expect_err("a foreign identity must not decrypt");
        assert!(matches!(err, SopsError::Decrypt(_)), "got {err:?}");
    }

    #[test]
    fn debug_never_prints_a_value() {
        let _env = EnvSandbox::acquire();
        let dir = tempfile::tempdir().unwrap();
        let (path, identity) = encrypted_document(dir.path(), DOC);
        let document = SecretDocument::load(&path, &identity).expect("the document must decrypt");

        let rendered = format!("{document:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    fn nested_fixture() -> Mapping {
        let mut inner = Mapping::new();
        inner.insert(Value::String("leaf".into()), Value::String("deep".into()));
        inner.insert(
            Value::String("tagged".into()),
            Value::Tagged(Box::new(TaggedValue {
                tag: Tag::new("custom"),
                value: Value::String("under-a-tag".into()),
            })),
        );

        let mut map = Mapping::new();
        map.insert(
            Value::String("password".into()),
            Value::String("hunter2".into()),
        );
        map.insert(Value::String("port".into()), Value::Number(5432.into()));
        map.insert(Value::String("nested".into()), Value::Mapping(inner));
        map.insert(
            Value::String("hosts".into()),
            Value::Sequence(vec![
                Value::String("one".into()),
                Value::Sequence(vec![Value::String("two".into())]),
            ]),
        );
        map
    }

    #[test]
    fn zeroizing_a_mapping_empties_every_string() {
        let mut map = nested_fixture();
        let wiped = zeroize_mapping(&mut map);

        assert!(map.is_empty(), "the mapping must be drained");
        assert_eq!(wiped.len(), 11, "{wiped:?}");
        for value in &wiped {
            assert!(value.is_empty(), "{wiped:?}");
        }
    }
}
