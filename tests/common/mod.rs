#![allow(dead_code)]
pub mod pty;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use age::secrecy::ExposeSecret;

pub const PLAINTEXT: &str = "db:\n    password: unchanged\n";

pub struct Key {
    pub path: PathBuf,
    pub recipient: String,
}

pub fn key(dir: &Path, name: &str) -> Key {
    let identity = age::x25519::Identity::generate();
    let path = dir.join(name);
    std::fs::write(&path, identity.to_string().expose_secret()).unwrap();
    Key {
        path,
        recipient: identity.to_public().to_string(),
    }
}

pub fn project() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".yett")).unwrap();
    dir
}

pub fn access_text(entries: &[(&str, &str, &str)]) -> String {
    let mut text = String::from("version: 1\npeople:\n");
    for (handle, tier, recipient) in entries {
        text.push_str(&format!(
            "  - handle: {handle}\n    keys:\n      {tier}: {recipient}\n"
        ));
    }
    text
}

pub fn write_access(dir: &Path, text: &str) {
    std::fs::write(dir.join(".yett/secrets-access.yaml"), text).unwrap();
}

pub fn yett(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_yett"))
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap()
}

pub fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

pub fn wrapped_data_key(ciphertext: &str, identity: &age::x25519::Identity) -> Vec<u8> {
    let yaml: serde_yaml::Value = serde_yaml::from_str(ciphertext).unwrap();
    let recipient = identity.to_public().to_string();
    let enc = yaml["sops"]["age"]
        .as_sequence()
        .unwrap()
        .iter()
        .find(|entry| entry["recipient"].as_str() == Some(&recipient))
        .and_then(|entry| entry["enc"].as_str())
        .unwrap();
    let decryptor = age::Decryptor::new(age::armor::ArmoredReader::new(enc.as_bytes())).unwrap();
    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .unwrap();
    let mut key = Vec::new();
    std::io::Read::read_to_end(&mut reader, &mut key).unwrap();
    key
}

pub fn identity_at(path: &Path) -> age::x25519::Identity {
    std::fs::read_to_string(path)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}
