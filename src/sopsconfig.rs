use std::str::FromStr;

use serde::Deserialize;

use crate::access::AgeRecipient;

#[derive(Debug, thiserror::Error)]
pub enum SopsConfigError {
    #[error("invalid SOPS YAML: {0}")]
    Yaml(serde_yaml::Error),
    #[error("SOPS age metadata is missing")]
    MissingAge,
    #[error("invalid SOPS age recipient")]
    InvalidRecipient,
}

#[derive(Deserialize)]
struct Document {
    sops: Metadata,
}

#[derive(Deserialize)]
struct Metadata {
    age: Vec<AgeEntry>,
}

#[derive(Deserialize)]
struct AgeEntry {
    recipient: String,
}

pub fn recipients_in_file(ciphertext: &str) -> Result<Vec<AgeRecipient>, SopsConfigError> {
    let document: Document = serde_yaml::from_str(ciphertext).map_err(SopsConfigError::Yaml)?;
    if document.sops.age.is_empty() {
        return Err(SopsConfigError::MissingAge);
    }
    document
        .sops
        .age
        .into_iter()
        .map(|entry| {
            AgeRecipient::from_str(&entry.recipient).map_err(|_| SopsConfigError::InvalidRecipient)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_recipient_shape_written_by_rops() {
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public().to_string();
        let ciphertext = crate::sops::encrypt_yaml("value: secret\n", &recipient).unwrap();
        let parsed = recipients_in_file(&ciphertext).unwrap();
        assert_eq!(
            parsed.iter().map(ToString::to_string).collect::<Vec<_>>(),
            vec![recipient]
        );
        let yaml: serde_yaml::Value = serde_yaml::from_str(&ciphertext).unwrap();
        assert_eq!(
            yaml["sops"]["age"][0]["recipient"].as_str(),
            Some(parsed[0].to_string().as_str())
        );
    }
}
