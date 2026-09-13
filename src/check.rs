use std::path::{Path, PathBuf};

use crate::access::AccessList;
use crate::envfile::EnvFile;
use crate::error::Error;
use crate::r#ref::Ref;
use crate::resolver::Resolver;

pub const ACCESS_PATH: &str = ".yett/secrets-access.yaml";
pub const SOPS_CONFIG_PATH: &str = ".sops.yaml";
const SECRETS_DIR: &str = ".yett";

pub fn check(env_file: &Path, identity: Option<PathBuf>) -> Result<(), Error> {
    let access = AccessList::load(Path::new(ACCESS_PATH))
        .map_err(|error| Error::Usage(error.to_string()))?;
    let config = std::fs::read_to_string(SOPS_CONFIG_PATH).map_err(|error| {
        Error::AccessMismatch(format!("cannot read {SOPS_CONFIG_PATH}: {error}"))
    })?;
    crate::access::verify(&access, &config, Path::new(SECRETS_DIR))?;

    let file = EnvFile::load(env_file)?;
    let resolver = Resolver::with_identity(identity);
    for (_, value) in file.iter() {
        if Ref::is_ref(value) {
            resolver.resolve(&Ref::parse(value)?)?;
        }
    }
    Ok(())
}
