use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};

use crate::envfile::EnvFile;
use crate::error::Error;
use crate::resolver::Resolver;

pub fn run(env_file: &Path, identity: Option<PathBuf>, command: &[OsString]) -> Result<(), Error> {
    let snapshot: Vec<(OsString, OsString)> = std::env::vars_os().collect();

    let file = EnvFile::load(env_file)?;

    let mut to_resolve: BTreeMap<String, String> = BTreeMap::new();
    for (key, value) in file.iter() {
        if snapshot.iter().any(|(name, _)| name == OsStr::new(key)) {
            continue;
        }
        to_resolve.insert(key.to_string(), value.to_string());
    }

    let resolved = Resolver::with_identity(identity).resolve_env(&to_resolve)?;

    if command.is_empty() {
        return Err(Error::Usage("no command given".to_string()));
    }

    let mut child = std::process::Command::new(&command[0]);
    child.env_clear();
    child.envs(snapshot);
    child.envs(
        resolved
            .iter()
            .map(|(name, value)| (name.as_str(), value.expose_secret())),
    );
    child.args(&command[1..]);

    let error = child.exec();
    Err(Error::Usage(format!(
        "cannot execute `{}`: {error}",
        command[0].to_string_lossy()
    )))
}
