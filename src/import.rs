use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::dotenv::Dotenv;
use crate::envfile::Upsert;
use crate::error::Error;
use crate::r#ref::Ref;

pub fn import(
    from: &Path,
    tier: &str,
    env_file: &Path,
    identity: Option<PathBuf>,
    dry_run: bool,
    exclude: Option<&str>,
    force: bool,
) -> Result<(), Error> {
    let excluded = exclude
        .unwrap_or_default()
        .split(',')
        .filter(|key| !key.is_empty())
        .collect::<HashSet<_>>();
    let entries = Dotenv::load(from)
        .map_err(|error| Error::Usage(error.to_string()))?
        .into_entries()
        .into_iter()
        .filter(|(key, _)| !excluded.contains(key.as_str()))
        .collect::<Vec<_>>();
    let rendered = entries
        .iter()
        .map(|(key, value)| {
            let reference = match Ref::is_ref(value) {
                true => value.clone(),
                false => crate::edit::pointer_reference(tier, &format!("/{key}"))?.to_string(),
            };
            Ok((key.clone(), reference))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    if dry_run {
        for (key, reference) in rendered {
            println!("{key}={reference}");
        }
        return Ok(());
    }
    let pairs = rendered
        .iter()
        .map(|(key, reference)| (key.as_str(), reference.as_str()))
        .collect::<Vec<_>>();
    let upsert = Upsert::prepare_many(env_file, &pairs, force)?;
    let secrets = entries
        .into_iter()
        .filter(|(_, value)| !Ref::is_ref(value))
        .collect::<Vec<_>>();
    seal(tier, identity.as_deref(), &secrets)?;
    upsert.write()?;
    println!(
        "imported {} variables; you can now remove {} or keep it gitignored",
        rendered.len(),
        from.display()
    );
    Ok(())
}

fn seal(tier: &str, identity: Option<&Path>, values: &[(String, String)]) -> Result<(), Error> {
    if values.is_empty() {
        crate::edit::tier_path(tier)?;
        return Ok(());
    }
    let path = crate::edit::tier_path(tier)?;
    if path.is_file() {
        return crate::edit::merge(tier, identity, values);
    }
    let recipients = match std::fs::read_to_string(&path) {
        Ok(ciphertext) => crate::sopsconfig::recipients_in_file(&ciphertext)
            .map_err(|error| Error::Usage(format!("{}: {error}", path.display())))?
            .iter()
            .map(ToString::to_string)
            .collect(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            crate::edit::create_recipients(tier)?
        }
        Err(error) => {
            return Err(Error::Usage(format!(
                "cannot read {}: {error}",
                path.display()
            )))
        }
    };
    let map = values
        .iter()
        .map(|(key, value)| {
            (
                serde_yaml::Value::String(key.clone()),
                serde_yaml::Value::String(value.clone()),
            )
        })
        .collect::<serde_yaml::Mapping>();
    let plaintext = serde_yaml::to_string(&map)
        .map_err(|error| Error::Usage(format!("cannot render {}: {error}", path.display())))?;
    let ciphertext = crate::rops_bridge::encrypt_yaml_to(&plaintext, &recipients)?;
    crate::access::write_atomic(&path, &ciphertext)
}
