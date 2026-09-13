use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use secrecy::ExposeSecret;

const DOC: &str = concat!(
    "db:\n",
    "    password: hunter2\n",
    "shape:\n",
    "    nested:\n",
    "        leaf: deep\n",
);

struct Fixture {
    dir: tempfile::TempDir,
    key: PathBuf,
    secrets: PathBuf,
}

fn plaintext_key(dir: &Path, name: &str) -> (PathBuf, String) {
    let key = age::x25519::Identity::generate();
    let path = dir.join(name);
    std::fs::write(&path, key.to_string().expose_secret()).unwrap();
    (path, key.to_public().to_string())
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let (key, recipient) = plaintext_key(dir.path(), "dev.key");
    let secrets = dir.path().join("secrets.dev.enc.yaml");
    std::fs::write(&secrets, yett::sops::encrypt_yaml(DOC, &recipient).unwrap()).unwrap();

    Fixture { dir, key, secrets }
}

impl Fixture {
    fn reference(&self, fragment: &str) -> String {
        format!("ref+sops://{}{fragment}", self.secrets.display())
    }

    fn get(&self, fragment: &str) -> Output {
        yett(&[
            "--identity",
            self.key.to_str().unwrap(),
            "get",
            &self.reference(fragment),
        ])
    }
}

fn yett(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_yett"))
        .args(args)
        .output()
        .unwrap()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn get_prints_the_value_and_one_newline() {
    let f = fixture();

    let out = f.get("#/db/password");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&out), "hunter2\n");
    assert_eq!(stderr(&out), "");

    let out = f.get("#/shape/nested/leaf");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&out), "deep\n");
}

#[test]
fn a_missing_pointer_exits_three() {
    let f = fixture();
    let out = f.get("#/db/nope");

    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    assert_eq!(stdout(&out), "");
    assert!(
        stderr(&out).starts_with("yett: "),
        "{}",
        stderr(&out).escape_debug()
    );
    assert!(
        stderr(&out).contains("no value at /db/nope"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_non_scalar_pointer_exits_three() {
    let f = fixture();
    let out = f.get("#/shape");

    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    assert_eq!(stdout(&out), "");
    assert!(
        stderr(&out).contains("value at /shape is not a scalar"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_foreign_identity_exits_two() {
    let f = fixture();
    let (stranger, _) = plaintext_key(f.dir.path(), "stranger.key");

    let out = yett(&[
        "--identity",
        stranger.to_str().unwrap(),
        "get",
        &f.reference("#/db/password"),
    ]);

    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert_eq!(stdout(&out), "");
    assert!(
        stderr(&out).starts_with("yett: sops decryption failed: "),
        "{}",
        stderr(&out)
    );
    assert!(!stderr(&out).contains("hunter2"), "{}", stderr(&out));
}

#[test]
fn an_argument_without_a_tier_segment_exits_one() {
    let out = yett(&["get", "plain-string"]);

    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(stdout(&out), "");
    assert!(
        stderr(&out).contains("<tier>/<pointer>"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_clap_usage_error_exits_one() {
    let out = yett(&[]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(stdout(&out), "");
    assert!(stderr(&out).contains("Usage:"), "{}", stderr(&out));

    let out = yett(&["get"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));

    let out = yett(&["conjure", "x"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
}

#[test]
fn help_and_version_exit_zero() {
    for arg in ["--help", "--version"] {
        let out = yett(&[arg]);
        assert_eq!(out.status.code(), Some(0), "{arg}: {}", stderr(&out));
        assert_eq!(stderr(&out), "", "{arg}");
        assert!(!stdout(&out).is_empty(), "{arg}");
    }
}
