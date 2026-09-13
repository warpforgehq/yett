use crate::envfile::EnvFileError;
use crate::identity::IdentityError;
use crate::r#ref::RefError;
use crate::sops::SopsError;
use crate::BridgeError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Usage(String),
    #[error("{0}")]
    Decryption(String),
    #[error("{0}")]
    Unresolved(String),
    #[error("{0}")]
    AccessMismatch(String),
    #[error("cannot harden this process: {0}")]
    Hardening(String),
    #[error("interrupted by signal {0}")]
    Interrupted(i32),
}

impl Error {
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::Usage(_) => 1,
            Error::Decryption(_) => 2,
            Error::Unresolved(_) => 3,
            Error::AccessMismatch(_) => 4,
            Error::Hardening(_) => 1,
            Error::Interrupted(signal) => 128 + signal,
        }
    }
}

impl From<RefError> for Error {
    fn from(e: RefError) -> Self {
        Error::Usage(e.to_string())
    }
}

impl From<EnvFileError> for Error {
    fn from(e: EnvFileError) -> Self {
        Error::Usage(e.to_string())
    }
}

impl From<BridgeError> for Error {
    fn from(e: BridgeError) -> Self {
        match &e {
            BridgeError::Decrypt(_) => Error::Decryption(e.to_string()),
            BridgeError::Encrypt(_) => Error::Usage(e.to_string()),
        }
    }
}

impl From<IdentityError> for Error {
    fn from(e: IdentityError) -> Self {
        match &e {
            IdentityError::Decrypt { .. } => Error::Decryption(e.to_string()),
            _ => Error::Usage(e.to_string()),
        }
    }
}

impl From<SopsError> for Error {
    fn from(e: SopsError) -> Self {
        match e {
            SopsError::Decrypt(bridge) => Error::from(bridge),
            other => Error::Unresolved(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn each_variant_owns_one_exit_code() {
        let codes = [
            (Error::Usage("u".into()), 1),
            (Error::Decryption("d".into()), 2),
            (Error::Unresolved("r".into()), 3),
            (Error::AccessMismatch("a".into()), 4),
            (Error::Interrupted(2), 130),
            (Error::Interrupted(15), 143),
        ];
        for (error, want) in codes {
            assert_eq!(error.exit_code(), want, "{error:?}");
        }
    }

    #[test]
    fn every_ref_error_is_a_usage_error() {
        let errors = [
            RefError::NotARef,
            RefError::MissingSeparator,
            RefError::EmptyBackend,
            RefError::UnknownBackend("doppler".into()),
            RefError::EmptyPath,
            RefError::InvalidFragment("must start with `/`"),
            RefError::NotImplemented,
        ];
        for error in errors {
            let text = error.to_string();
            let mapped = Error::from(error);
            assert!(matches!(mapped, Error::Usage(_)), "{mapped:?}");
            assert_eq!(mapped.exit_code(), 1);
            assert_eq!(mapped.to_string(), text);
        }
    }

    #[test]
    fn a_reserved_backend_is_a_usage_error() {
        let mapped = Error::from(RefError::NotImplemented);
        assert_eq!(mapped.to_string(), "backend not implemented");
        assert_eq!(mapped.exit_code(), 1);
    }

    #[test]
    fn bridge_decryption_is_code_two_and_encryption_is_code_one() {
        let decrypt = Error::from(BridgeError::Decrypt("no key".into()));
        assert!(matches!(decrypt, Error::Decryption(_)), "{decrypt:?}");
        assert_eq!(decrypt.exit_code(), 2);

        let encrypt = Error::from(BridgeError::Encrypt("bad recipient".into()));
        assert!(matches!(encrypt, Error::Usage(_)), "{encrypt:?}");
        assert_eq!(encrypt.exit_code(), 1);
    }

    #[test]
    fn a_wrong_passphrase_is_code_two_and_other_identity_faults_are_code_one() {
        let wrong = Error::from(IdentityError::Decrypt {
            path: PathBuf::from("/k/dev.key.age"),
            source: age::DecryptError::NoMatchingKeys,
        });
        assert!(matches!(wrong, Error::Decryption(_)), "{wrong:?}");
        assert_eq!(wrong.exit_code(), 2);

        let others = [
            IdentityError::MalformedKey("invalid"),
            IdentityError::Read {
                path: PathBuf::from("/k/dev.key.age"),
                source: std::io::Error::other("gone"),
            },
            IdentityError::PlaintextAtDefaultPath(PathBuf::from("/k/dev.key.age")),
            IdentityError::UnrecognizedFormat(PathBuf::from("/k/dev.key.age")),
            IdentityError::NoKeyInPayload(PathBuf::from("/k/dev.key.age")),
            IdentityError::Prompt {
                tier: "dev".into(),
                source: std::io::Error::other("not a tty"),
            },
        ];
        for error in others {
            let mapped = Error::from(error);
            assert!(matches!(mapped, Error::Usage(_)), "{mapped:?}");
            assert_eq!(mapped.exit_code(), 1);
        }
    }

    #[test]
    fn document_faults_are_code_three_except_a_failed_decryption() {
        let unresolved = [
            SopsError::Read {
                path: PathBuf::from("secrets.dev.enc.yaml"),
                source: std::io::Error::other("gone"),
            },
            SopsError::MissingKey {
                path: PathBuf::from("secrets.dev.enc.yaml"),
                pointer: "/db/nope".into(),
            },
            SopsError::NotAScalar {
                path: PathBuf::from("secrets.dev.enc.yaml"),
                pointer: "/db".into(),
            },
        ];
        for error in unresolved {
            let mapped = Error::from(error);
            assert!(matches!(mapped, Error::Unresolved(_)), "{mapped:?}");
            assert_eq!(mapped.exit_code(), 3);
        }

        let mapped = Error::from(SopsError::Decrypt(BridgeError::Decrypt("no key".into())));
        assert!(matches!(mapped, Error::Decryption(_)), "{mapped:?}");
        assert_eq!(mapped.exit_code(), 2);
    }
}
