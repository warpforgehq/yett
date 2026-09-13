use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::access::AccessList;
use crate::check::ACCESS_PATH;
use crate::error::Error;
use crate::harden::{PageLocks, SecretBuf};
use crate::identity::{IdentityStore, TtyPrompt};
use crate::r#ref::decode_pointer;
use crate::sops::zeroize_mapping;
use crate::{access, rops_bridge, sopsconfig};

mod ram;
mod signal;

use signal::{install_handlers, interrupted_signal, spawn};

const SECRETS_DIR: &str = ".yett";

pub fn set(tier: &str, pointer: &str, identity: Option<PathBuf>) -> Result<(), Error> {
    set_with_ref(tier, pointer, identity, Path::new(".env.refs"), None)
}

pub fn set_with_ref(
    tier: &str,
    pointer: &str,
    identity: Option<PathBuf>,
    env_file: &Path,
    reference_name: Option<&str>,
) -> Result<(), Error> {
    let pointer = normalize_pointer(pointer)?;
    let reference = pointer_reference(tier, &pointer)?;
    let upsert = reference_name
        .map(|name| crate::envfile::Upsert::prepare(env_file, name, &reference.to_string()))
        .transpose()?;
    let segments = decode_pointer(&pointer)?;
    let Some((leaf, parents)) = segments.split_last() else {
        return Err(Error::Usage(
            "the pointer must name a key, for example db/password".to_string(),
        ));
    };
    let value = read_value()?;

    let (mut file, created) = TierFile::open_or_create(tier, identity.as_deref())?;
    insert(&mut file.map, parents, leaf, value.as_str())?;
    file.relock();
    let plaintext = file.plaintext()?;
    if !created {
        file.seal(plaintext.as_str())?;
    } else {
        match file.seal_new(plaintext.as_str())? {
            access::Publish::Created => {}
            access::Publish::AlreadyExists => {
                drop(file);
                let mut existing = TierFile::open(tier, identity.as_deref())?;
                insert(&mut existing.map, parents, leaf, value.as_str())?;
                existing.relock();
                let plaintext = existing.plaintext()?;
                existing.seal(plaintext.as_str())?;
            }
        }
    }
    if let Some(upsert) = upsert {
        upsert.write()?;
    }
    Ok(())
}

pub fn edit(tier: &str, identity: Option<PathBuf>) -> Result<(), Error> {
    let editor = std::env::var("EDITOR").ok();
    editor_words(editor.as_deref())?;

    let file = TierFile::open(tier, identity.as_deref())?;
    let plaintext = file.plaintext()?;

    install_handlers();
    let workspace = ram::Workspace::create(tier)?;
    workspace.write(plaintext.as_str())?;
    drop(plaintext);

    let argv = editor_argv(editor.as_deref(), workspace.path())?;
    if let Some(signal) = interrupted_signal() {
        return Err(Error::Interrupted(signal));
    }
    let status = spawn(&argv)?;
    if let Some(signal) = interrupted_signal() {
        return Err(Error::Interrupted(signal));
    }
    if let Some(signal) = std::os::unix::process::ExitStatusExt::signal(&status) {
        return Err(Error::Interrupted(signal));
    }
    if !status.success() {
        return Err(Error::Usage(format!("`{}` exited with {status}", argv[0])));
    }

    let edited = SecretBuf::from_zeroizing(Zeroizing::new(workspace.read()?.into_bytes()));
    drop(workspace);

    let mut parsed: serde_yaml::Mapping = serde_yaml::from_str(edited.as_str())
        .map_err(|error| Error::Usage(format!("the edited document is unusable: {error}")))?;
    let _wiped = zeroize_mapping(&mut parsed);

    file.seal(edited.as_str())
}

struct TierFile {
    path: PathBuf,
    recipients: Vec<String>,
    map: serde_yaml::Mapping,
    locks: PageLocks,
}

impl TierFile {
    fn open(tier: &str, identity: Option<&Path>) -> Result<Self, Error> {
        let path = tier_path(tier)?;
        if !path.is_file() {
            return Err(Error::Usage(format!(
                "{} does not exist; create it first, for example with `sops --encrypt`",
                path.display()
            )));
        }
        let ciphertext = std::fs::read_to_string(&path)
            .map_err(|error| Error::Usage(format!("cannot read {}: {error}", path.display())))?;
        let recipients = sopsconfig::recipients_in_file(&ciphertext)
            .map_err(|error| Error::Usage(format!("{}: {error}", path.display())))?
            .iter()
            .map(ToString::to_string)
            .collect();
        let key = IdentityStore::new().load(tier, identity, &mut TtyPrompt)?;
        let map = rops_bridge::decrypt_yaml(&ciphertext, &key)?;
        let locks = PageLocks::for_mapping(&map);
        Ok(TierFile {
            path,
            recipients,
            map,
            locks,
        })
    }

    fn open_or_create(tier: &str, identity: Option<&Path>) -> Result<(Self, bool), Error> {
        let path = tier_path(tier)?;
        if path.is_file() {
            return Self::open(tier, identity).map(|file| (file, false));
        }
        let recipients = create_recipients(tier)?;
        let map = serde_yaml::Mapping::new();
        let locks = PageLocks::for_mapping(&map);
        Ok((
            TierFile {
                path,
                recipients,
                map,
                locks,
            },
            true,
        ))
    }

    fn relock(&mut self) {
        self.locks = PageLocks::for_mapping(&self.map);
    }

    fn plaintext(&self) -> Result<SecretBuf, Error> {
        let text = Zeroizing::new(
            serde_yaml::to_string(&self.map)
                .map_err(|error| {
                    Error::Usage(format!("cannot render {}: {error}", self.path.display()))
                })?
                .into_bytes(),
        );
        Ok(SecretBuf::from_zeroizing(text))
    }

    fn seal(&self, plaintext: &str) -> Result<(), Error> {
        let ciphertext = rops_bridge::encrypt_yaml_to(plaintext, &self.recipients)?;
        access::write_atomic(&self.path, &ciphertext)
    }

    fn seal_new(&self, plaintext: &str) -> Result<access::Publish, Error> {
        let ciphertext = rops_bridge::encrypt_yaml_to(plaintext, &self.recipients)?;
        access::publish_new(&self.path, &ciphertext)
    }
}

impl Drop for TierFile {
    fn drop(&mut self) {
        let _wiped = zeroize_mapping(&mut self.map);
    }
}

fn normalize_pointer(pointer: &str) -> Result<String, Error> {
    let body = pointer.strip_prefix('#').unwrap_or(pointer);
    if body.is_empty() {
        return Err(Error::Usage(
            "the pointer must name a key, for example db/password".to_string(),
        ));
    }
    if body.starts_with('/') {
        Ok(body.to_string())
    } else {
        Ok(format!("/{body}"))
    }
}

pub fn pointer_reference(tier: &str, pointer: &str) -> Result<crate::r#ref::Ref, Error> {
    decode_pointer(pointer)?;
    let path = tier_path(tier)?;
    Ok(crate::r#ref::Ref::parse(&format!(
        "ref+sops://{}#{pointer}",
        path.display()
    ))?)
}

fn tier_path(tier: &str) -> Result<PathBuf, Error> {
    let named = !tier.is_empty()
        && tier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !named {
        return Err(Error::Usage(format!(
            "invalid tier name `{tier}`; use letters, digits, `_` and `-`"
        )));
    }
    Ok(Path::new(SECRETS_DIR).join(format!("secrets.{tier}.enc.yaml")))
}

fn create_recipients(tier: &str) -> Result<Vec<String>, Error> {
    let access =
        AccessList::load(Path::new(ACCESS_PATH)).map_err(|error| unconfigured(tier, &error))?;
    let recipients = access
        .recipients(tier)
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    match recipients.is_empty() {
        true => Err(unconfigured(
            tier,
            &format!("{ACCESS_PATH} has no recipients for tier `{tier}`"),
        )),
        false => Ok(recipients),
    }
}

fn unconfigured(tier: &str, detail: &dyn std::fmt::Display) -> Error {
    Error::Usage(format!(
        "{detail}; run `yett access add <handle> {tier} <public-key>` then `yett access sync`"
    ))
}

fn read_value() -> Result<SecretBuf, Error> {
    use std::io::Read;

    let mut raw = Zeroizing::new(Vec::new());
    std::io::stdin()
        .lock()
        .read_to_end(&mut raw)
        .map_err(|error| Error::Usage(format!("cannot read the value from stdin: {error}")))?;
    let text = std::str::from_utf8(&raw)
        .map_err(|_| Error::Usage("the value on stdin is not valid UTF-8".to_string()))?;
    let value = text.strip_suffix('\n').unwrap_or(text);
    if value.is_empty() {
        return Err(Error::Usage(
            "the value on stdin is empty; pipe the secret into `yett set`".to_string(),
        ));
    }
    Ok(SecretBuf::new(value))
}

fn insert(
    map: &mut serde_yaml::Mapping,
    parents: &[String],
    leaf: &str,
    value: &str,
) -> Result<(), Error> {
    let mut current = map;
    for (depth, segment) in parents.iter().enumerate() {
        let entry = current
            .entry(serde_yaml::Value::String(segment.clone()))
            .or_insert_with(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
        current = match entry {
            serde_yaml::Value::Mapping(inner) => inner,
            _ => {
                return Err(Error::Usage(format!(
                    "{} is not a mapping",
                    pointer_text(&parents[..=depth])
                )))
            }
        };
    }
    current.insert(
        serde_yaml::Value::String(leaf.to_string()),
        serde_yaml::Value::String(value.to_string()),
    );
    Ok(())
}

fn pointer_text(segments: &[String]) -> String {
    segments
        .iter()
        .map(|segment| format!("/{segment}"))
        .collect()
}

fn no_editor() -> Error {
    Error::Usage(
        "$EDITOR is not set; set it to the editor `yett edit` should run, or use `yett set`"
            .to_string(),
    )
}

fn editor_words(editor: Option<&str>) -> Result<Vec<String>, Error> {
    let Some(text) = editor else {
        return Err(no_editor());
    };
    let mut words = Vec::new();
    let mut current = String::new();
    let mut started = false;
    let mut quote: Option<char> = None;
    let mut chars = text.chars();
    while let Some(character) = chars.next() {
        if let Some(open) = quote {
            if character == open {
                quote = None;
            } else if open == '"' && character == '\\' {
                match chars.next() {
                    Some(escaped) => {
                        if escaped == '"' || escaped == '\\' {
                            current.push(escaped);
                        } else {
                            current.push('\\');
                            current.push(escaped);
                        }
                    }
                    None => {
                        return Err(Error::Usage(
                            "$EDITOR ends with a dangling backslash".to_string(),
                        ))
                    }
                }
            } else {
                current.push(character);
            }
            continue;
        }
        match character {
            '\'' | '"' => {
                quote = Some(character);
                started = true;
            }
            '\\' => match chars.next() {
                Some(escaped) => {
                    current.push(escaped);
                    started = true;
                }
                None => {
                    return Err(Error::Usage(
                        "$EDITOR ends with a dangling backslash".to_string(),
                    ))
                }
            },
            _ if character.is_whitespace() => {
                if started {
                    words.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            _ => {
                current.push(character);
                started = true;
            }
        }
    }
    if quote.is_some() {
        return Err(Error::Usage(
            "$EDITOR has an unterminated quote; fix the editor command".to_string(),
        ));
    }
    if started {
        words.push(current);
    }
    if words.is_empty() {
        return Err(no_editor());
    }
    Ok(words)
}

fn editor_argv(editor: Option<&str>, path: &Path) -> Result<Vec<String>, Error> {
    let mut argv = editor_words(editor)?;
    argv.push(path.display().to_string());
    Ok(argv)
}

#[cfg(test)]
mod tests;
