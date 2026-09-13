use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use super::AccessList;
fn unique_temp(path: &Path) -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".{}.{nanos}.{counter}.tmp", std::process::id()));
    PathBuf::from(name)
}

pub(super) fn write_atomic_io(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let temporary = unique_temp(path);
    let mode = std::fs::metadata(path)
        .map(|metadata| metadata.permissions().mode())
        .unwrap_or(0o644);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temporary)?;
    if let Err(error) = file.write_all(contents.as_bytes()) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    drop(file);
    if let Err(error) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(())
}

pub fn write_atomic(path: &Path, contents: &str) -> Result<(), crate::Error> {
    write_atomic_io(path, contents)
        .map_err(|error| crate::Error::Usage(format!("cannot write {}: {error}", path.display())))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Publish {
    Created,
    AlreadyExists,
}

fn publish_new_io(path: &Path, contents: &str) -> std::io::Result<Publish> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let temporary = unique_temp(path);
    let mode = std::fs::metadata(path)
        .map(|metadata| metadata.permissions().mode())
        .unwrap_or(0o644);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temporary)?;
    if let Err(error) = file.write_all(contents.as_bytes()) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    drop(file);
    let published = match std::fs::hard_link(&temporary, path) {
        Ok(()) => Publish::Created,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Publish::AlreadyExists,
        Err(error) => {
            let _ = std::fs::remove_file(&temporary);
            return Err(error);
        }
    };
    let _ = std::fs::remove_file(&temporary);
    Ok(published)
}

pub fn publish_new(path: &Path, contents: &str) -> Result<Publish, crate::Error> {
    publish_new_io(path, contents)
        .map_err(|error| crate::Error::Usage(format!("cannot write {}: {error}", path.display())))
}

pub fn stage(path: &Path, contents: &str) -> Result<PathBuf, crate::Error> {
    let temporary = unique_temp(path);
    std::fs::write(&temporary, contents).map_err(|error| {
        let _ = std::fs::remove_file(&temporary);
        crate::Error::Usage(format!("cannot write {}: {error}", temporary.display()))
    })?;
    Ok(temporary)
}

pub fn commit(temporary: &Path, path: &Path) -> Result<(), crate::Error> {
    std::fs::rename(temporary, path)
        .map_err(|error| crate::Error::Usage(format!("cannot replace {}: {error}", path.display())))
}

pub struct SyncRollback {
    files: Vec<(PathBuf, String)>,
}

impl SyncRollback {
    pub fn rollback(&self) {
        for (path, original) in &self.files {
            let _ = write_atomic_io(path, original);
        }
    }
}

pub fn verify(
    access: &AccessList,
    config_text: &str,
    secrets_dir: &Path,
) -> Result<(), crate::Error> {
    if access.render_sops_config() != config_text {
        return Err(crate::Error::AccessMismatch(
            ".sops.yaml does not match secrets-access.yaml".into(),
        ));
    }
    let entries = std::fs::read_dir(secrets_dir).map_err(|error| {
        crate::Error::AccessMismatch(format!("cannot inspect encrypted files: {error}"))
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            crate::Error::AccessMismatch(format!("cannot inspect encrypted files: {error}"))
        })?;
        let Some(tier) = crate::identity::tier_from_secret_path(&entry.path()) else {
            continue;
        };
        let ciphertext = std::fs::read_to_string(entry.path()).map_err(|error| {
            crate::Error::AccessMismatch(format!("cannot read encrypted file: {error}"))
        })?;
        let actual = crate::sopsconfig::recipients_in_file(&ciphertext).map_err(|error| {
            crate::Error::AccessMismatch(format!("cannot inspect encrypted file: {error}"))
        })?;
        if actual.into_iter().collect::<BTreeSet<_>>()
            != access
                .recipients(&tier)
                .into_iter()
                .collect::<BTreeSet<_>>()
        {
            return Err(crate::Error::AccessMismatch(format!(
                "encrypted recipients for {tier} do not match the access list"
            )));
        }
    }
    Ok(())
}

pub fn check_tiers_keep_recipients(
    access: &AccessList,
    secrets_dir: &Path,
    tiers: &[String],
) -> Result<(), crate::Error> {
    for tier in tiers {
        let path = secrets_dir.join(format!("secrets.{tier}.enc.yaml"));
        if !path.is_file() {
            continue;
        }
        if access.recipients(tier).is_empty() {
            return Err(crate::Error::Usage(format!(
                "refusing to strip the last recipient from {tier}: add a replacement recipient first or delete {}",
                path.display()
            )));
        }
    }
    Ok(())
}

pub fn sync(
    access: &AccessList,
    secrets_dir: &Path,
    identity_path: Option<&Path>,
) -> Result<(), crate::Error> {
    use crate::identity::{IdentityStore, TtyPrompt};
    let store = IdentityStore::new();
    let mut prompt = TtyPrompt;
    let mut tiers = access
        .tiers()
        .into_iter()
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    let entries = std::fs::read_dir(secrets_dir).map_err(|error| {
        crate::Error::Usage(format!("cannot inspect {}: {error}", secrets_dir.display()))
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| crate::Error::Usage(error.to_string()))?;
        if let Some(tier) = crate::identity::tier_from_secret_path(&entry.path()) {
            tiers.insert(tier);
        }
    }
    let mut updates: Vec<(PathBuf, String, String)> = Vec::new();
    for tier in &tiers {
        let path = secrets_dir.join(format!("secrets.{tier}.enc.yaml"));
        if !path.is_file() {
            continue;
        }
        let ciphertext = std::fs::read_to_string(&path).map_err(|error| {
            crate::Error::Usage(format!("cannot read {}: {error}", path.display()))
        })?;
        let current = crate::sopsconfig::recipients_in_file(&ciphertext)
            .map_err(|error| crate::Error::Usage(error.to_string()))?;
        let wanted = access.recipients(tier);
        let current_set = current
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>();
        let wanted_set = wanted
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>();
        if current_set == wanted_set || wanted_set.is_empty() {
            continue;
        }
        let remove = current_set
            .difference(&wanted_set)
            .cloned()
            .collect::<Vec<_>>();
        let add = wanted_set
            .difference(&current_set)
            .cloned()
            .collect::<Vec<_>>();
        let identity = store.load(tier, identity_path, &mut prompt)?;
        if remove.iter().any(|key| key == identity.recipient()) {
            return Err(crate::Error::Usage(format!(
                "the identity running sync would lose access to {tier}; have the replacement recipient run sync"
            )));
        }
        let updated = crate::rops_bridge::update_recipients(&ciphertext, &identity, &remove, &add)?;
        updates.push((path, ciphertext, updated));
    }
    let mut rollback = SyncRollback { files: Vec::new() };
    for (path, original, updated) in updates {
        if let Err(error) = write_atomic(&path, &updated) {
            rollback.rollback();
            return Err(error);
        }
        rollback.files.push((path, original));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_leftovers(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".tmp"))
            .collect()
    }

    #[test]
    fn publish_new_creates_then_reports_exists_without_leaving_temps() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.dev.enc.yaml");

        assert_eq!(
            publish_new_io(&path, "ciphertext").unwrap(),
            Publish::Created
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "ciphertext");
        assert!(temp_leftovers(dir.path()).is_empty());

        assert_eq!(
            publish_new_io(&path, "other").unwrap(),
            Publish::AlreadyExists
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "ciphertext");
        assert!(temp_leftovers(dir.path()).is_empty());
    }

    #[test]
    fn write_atomic_still_replaces_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.dev.enc.yaml");

        write_atomic_io(&path, "first").unwrap();
        write_atomic_io(&path, "second").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "second");
        assert!(temp_leftovers(dir.path()).is_empty());
    }
}
