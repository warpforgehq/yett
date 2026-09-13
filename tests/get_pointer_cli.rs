mod common;

use std::io::Write;
use std::process::{Command, Output, Stdio};

use common::{key, project, stderr, write_access, Key};

struct Fixture {
    dir: tempfile::TempDir,
    key: Key,
}

fn fixture() -> Fixture {
    let dir = project();
    let key = key(dir.path(), "dev.key");
    let access = format!(
        "version: 1\npeople:\n  - handle: ephor\n    keys:\n      dev: {r}\n      staging: {r}\n",
        r = key.recipient
    );
    write_access(dir.path(), &access);
    Fixture { dir, key }
}

impl Fixture {
    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_yett"));
        command.current_dir(self.dir.path()).args(args);
        for name in [
            "YETT_IDENTITY",
            "ROPS_AGE",
            "ROPS_AGE_KEY_FILE",
            "XDG_CONFIG_HOME",
            "HOME",
        ] {
            command.env_remove(name);
        }
        command
    }

    fn identity(&self) -> &str {
        self.key.path.to_str().unwrap()
    }

    fn set(&self, tier: &str, pointer: &str, value: &str) -> Output {
        let mut child = self
            .command(&["--identity", self.identity(), "set", tier, pointer])
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
        child.wait_with_output().unwrap()
    }

    fn get(&self, argument: &str) -> Output {
        self.command(&["--identity", self.identity(), "get", argument])
            .output()
            .unwrap()
    }
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn a_tier_pointer_resolves_against_that_tier() {
    let f = fixture();
    let out = f.set("dev", "/db/url", "postgres://dev\n");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));

    let out = f.get("dev/db/url");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&out), "postgres://dev\n");
}

#[test]
fn the_first_segment_selects_the_file() {
    let f = fixture();
    assert_eq!(
        f.set("dev", "/db/url", "postgres://dev\n").status.code(),
        Some(0)
    );
    assert_eq!(
        f.set("staging", "/db/url", "postgres://staging\n")
            .status
            .code(),
        Some(0)
    );

    let out = f.get("dev/db/url");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&out), "postgres://dev\n");

    let out = f.get("staging/db/url");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&out), "postgres://staging\n");
}

#[test]
fn a_full_reference_still_resolves() {
    let f = fixture();
    assert_eq!(
        f.set("dev", "/db/url", "postgres://dev\n").status.code(),
        Some(0)
    );

    let out = f.get("ref+sops://.yett/secrets.dev.enc.yaml#/db/url");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&out), "postgres://dev\n");
}

#[test]
fn a_missing_pointer_exits_three() {
    let f = fixture();
    assert_eq!(
        f.set("dev", "/db/url", "postgres://dev\n").status.code(),
        Some(0)
    );

    let out = f.get("dev/missing");
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    assert_eq!(stdout(&out), "");
}

#[test]
fn a_missing_tier_file_exits_three() {
    let f = fixture();

    let out = f.get("staging/db/url");
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    assert_eq!(stdout(&out), "");
}

#[test]
fn a_foreign_identity_exits_two() {
    let f = fixture();
    assert_eq!(
        f.set("dev", "/db/url", "postgres://dev\n").status.code(),
        Some(0)
    );
    let stranger = key(f.dir.path(), "stranger.key");

    let out = f
        .command(&[
            "--identity",
            stranger.path.to_str().unwrap(),
            "get",
            "dev/db/url",
        ])
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert_eq!(stdout(&out), "");
    assert!(!stderr(&out).contains("postgres://dev"), "{}", stderr(&out));
}

#[test]
fn malformed_arguments_exit_one() {
    let f = fixture();

    for argument in ["dev", "dev/", "/db/url", "de|v/db/url"] {
        let out = f.get(argument);
        assert_eq!(out.status.code(), Some(1), "{argument}: {}", stderr(&out));
        assert_eq!(stdout(&out), "", "{argument}");
    }
}

#[test]
fn set_accepts_a_pointer_without_the_leading_slash() {
    let f = fixture();

    let out = f.set("dev", "db/url", "postgres://dev\n");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&f.get("dev/db/url")), "postgres://dev\n");

    let slash = f.set("dev", "/db/url2", "second\n");
    assert_eq!(slash.status.code(), Some(0), "{}", stderr(&slash));
    assert_eq!(stdout(&f.get("dev/db/url2")), "second\n");

    let empty = f.set("dev", "", "x\n");
    assert_eq!(empty.status.code(), Some(1));
}
