mod common;

use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};

use common::{access_text, key, project, stderr, write_access, Key};

struct Fixture {
    dir: tempfile::TempDir,
    key: Key,
}

fn fixture() -> Fixture {
    let dir = project();
    let key = key(dir.path(), "dev.key");
    Fixture { dir, key }
}

fn command(dir: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_yett"));
    command.current_dir(dir);
    for name in ["YETT_IDENTITY", "ROPS_AGE", "ROPS_AGE_KEY_FILE", "EDITOR"] {
        command.env_remove(name);
    }
    command
}

fn start_set(f: &Fixture, pointer: &str, value: &str) -> Child {
    let mut child = command(f.dir.path())
        .args([
            "--identity",
            f.key.path.to_str().unwrap(),
            "set",
            "dev",
            pointer,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(value.as_bytes())
        .unwrap();
    child
}

fn value(f: &Fixture, fragment: &str) -> String {
    let reference = format!("ref+sops://.yett/secrets.dev.enc.yaml{fragment}");
    let out: Output = command(f.dir.path())
        .args([
            "--identity",
            f.key.path.to_str().unwrap(),
            "get",
            &reference,
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn temp_files(f: &Fixture) -> Vec<String> {
    std::fs::read_dir(f.dir.path().join(".yett"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".tmp"))
        .collect()
}

#[test]
fn concurrent_creates_both_succeed_and_keep_their_keys() {
    for attempt in 0..10 {
        let f = fixture();
        write_access(
            f.dir.path(),
            &access_text(&[("ephor", "dev", &f.key.recipient)]),
        );

        let alpha = format!("alpha-{attempt}\n");
        let beta = format!("beta-{attempt}\n");
        let first = start_set(&f, "/alpha", &alpha);
        let second = start_set(&f, "/beta", &beta);
        let first = first.wait_with_output().unwrap();
        let second = second.wait_with_output().unwrap();

        assert_eq!(
            first.status.code(),
            Some(0),
            "attempt {attempt} /alpha: {}",
            stderr(&first)
        );
        assert_eq!(
            second.status.code(),
            Some(0),
            "attempt {attempt} /beta: {}",
            stderr(&second)
        );
        assert_eq!(value(&f, "#/alpha"), alpha, "attempt {attempt}");
        assert_eq!(value(&f, "#/beta"), beta, "attempt {attempt}");
        assert!(
            temp_files(&f).is_empty(),
            "attempt {attempt}: left temp files"
        );
    }
}
