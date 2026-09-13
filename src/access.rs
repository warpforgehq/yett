use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

mod sync;

pub use sync::{
    check_tiers_keep_recipients, commit, publish_new, stage, sync, verify, write_atomic, Publish,
};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AgeRecipient(String);

impl Display for AgeRecipient {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for AgeRecipient {
    type Err = AccessError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty() {
            return Err(AccessError::EmptyKey);
        }
        age::x25519::Recipient::from_str(value)
            .map(|_| Self(value.to_string()))
            .map_err(|_| AccessError::InvalidRecipient)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AccessError {
    #[error("cannot read access list {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot write access list {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid access list: {0}")]
    Yaml(serde_yaml::Error),
    #[error("unsupported access list version {0}; expected 1")]
    Version(u64),
    #[error("duplicate handle {0}")]
    DuplicateHandle(String),
    #[error("handle `{0}` is not in the access list")]
    UnknownHandle(String),
    #[error("handle must not be empty")]
    EmptyHandle,
    #[error("recipient key must not be empty")]
    EmptyKey,
    #[error("invalid native age recipient")]
    InvalidRecipient,
    #[error("tier must not be empty")]
    EmptyTier,
    #[error("invalid tier name `{0}`; use letters, digits, `_` and `-`")]
    InvalidTier(String),
}

fn is_valid_tier(tier: &str) -> bool {
    !tier.is_empty()
        && tier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AccessFile {
    version: u64,
    people: Vec<PersonFile>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersonFile {
    handle: String,
    keys: BTreeMap<String, String>,
}

pub struct AccessList {
    version: u64,
    people: Vec<Person>,
}

struct Person {
    handle: String,
    keys: BTreeMap<String, AgeRecipient>,
}

impl AccessList {
    pub fn load(path: &Path) -> Result<Self, AccessError> {
        let text = std::fs::read_to_string(path).map_err(|source| AccessError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let raw: AccessFile = serde_yaml::from_str(&text).map_err(AccessError::Yaml)?;
        if raw.version != 1 {
            return Err(AccessError::Version(raw.version));
        }
        let mut handles = BTreeSet::new();
        let mut people = Vec::with_capacity(raw.people.len());
        for raw_person in raw.people {
            if raw_person.handle.is_empty() {
                return Err(AccessError::EmptyHandle);
            }
            if !handles.insert(raw_person.handle.clone()) {
                return Err(AccessError::DuplicateHandle(raw_person.handle));
            }
            let mut keys = BTreeMap::new();
            for (tier, key) in raw_person.keys {
                if tier.is_empty() {
                    return Err(AccessError::EmptyTier);
                }
                if !is_valid_tier(&tier) {
                    return Err(AccessError::InvalidTier(tier));
                }
                keys.insert(tier, AgeRecipient::from_str(&key)?);
            }
            people.push(Person {
                handle: raw_person.handle,
                keys,
            });
        }
        Ok(Self {
            version: raw.version,
            people,
        })
    }

    pub fn to_text(&self) -> Result<String, AccessError> {
        let raw = AccessFile {
            version: self.version,
            people: self
                .people
                .iter()
                .map(|person| PersonFile {
                    handle: person.handle.clone(),
                    keys: person
                        .keys
                        .iter()
                        .map(|(tier, key)| (tier.clone(), key.to_string()))
                        .collect(),
                })
                .collect(),
        };
        serde_yaml::to_string(&raw).map_err(AccessError::Yaml)
    }

    pub fn save(&self, path: &Path) -> Result<(), AccessError> {
        let text = self.to_text()?;
        sync::write_atomic_io(path, &text).map_err(|source| AccessError::Write {
            path: path.to_path_buf(),
            source,
        })
    }

    pub fn recipients(&self, tier: &str) -> Vec<AgeRecipient> {
        let mut seen = BTreeSet::new();
        self.people
            .iter()
            .filter_map(|person| person.keys.get(tier).cloned())
            .filter(|recipient| seen.insert(recipient.clone()))
            .collect()
    }

    pub fn render_sops_config(&self) -> String {
        let mut output = String::from(
            "# generated by yett — edit secrets-access.yaml instead\ncreation_rules:\n",
        );
        for tier in self.tiers() {
            let recipients = self
                .recipients(tier)
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            output.push_str(&format!("  - path_regex: \\.yett/secrets\\.{tier}\\.enc\\.yaml$\n    key_groups: [{{ age: [{recipients}] }}]\n"));
        }
        output
    }

    pub fn add(&mut self, handle: &str, tier: &str, key: &str) -> Result<(), AccessError> {
        if handle.is_empty() {
            return Err(AccessError::EmptyHandle);
        }
        if tier.is_empty() {
            return Err(AccessError::EmptyTier);
        }
        if !is_valid_tier(tier) {
            return Err(AccessError::InvalidTier(tier.to_string()));
        }
        let recipient = AgeRecipient::from_str(key)?;
        if let Some(person) = self
            .people
            .iter_mut()
            .find(|person| person.handle == handle)
        {
            person.keys.insert(tier.to_string(), recipient);
        } else {
            self.people.push(Person {
                handle: handle.to_string(),
                keys: BTreeMap::from([(tier.to_string(), recipient)]),
            });
        }
        Ok(())
    }

    pub fn remove(&mut self, handle: &str) -> Result<Vec<String>, AccessError> {
        let Some(index) = self
            .people
            .iter()
            .position(|person| person.handle == handle)
        else {
            return Err(AccessError::UnknownHandle(handle.to_string()));
        };
        let person = self.people.remove(index);
        Ok(person.keys.into_keys().collect())
    }

    pub fn handles(&self) -> Vec<&str> {
        self.people
            .iter()
            .map(|person| person.handle.as_str())
            .collect()
    }

    pub(crate) fn tiers(&self) -> BTreeSet<&str> {
        self.people
            .iter()
            .flat_map(|person| person.keys.keys().map(String::as_str))
            .collect()
    }
}
