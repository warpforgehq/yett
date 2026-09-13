mod common;

use std::path::Path;
use std::process::{Command, Output};

use common::{access_text, key, project, stderr, write_access, Key};

const DOC: &str = concat!("db:\n", "    password: hunter2\n");

const ENV_REFS: &str = concat!(
    "LOG_LEVEL=debug\n",
    "DATABASE_PASSWORD=ref+sops://.yett/secrets.dev.enc.yaml#/db/password\n",
);

struct Fixture {
    dir: tempfile::TempDir,
    alice: Key,
}

fn yett(dir: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_yett"));
    command.current_dir(dir).args(args);
    for name in ["YETT_IDENTITY", "ROPS_AGE", "ROPS_AGE_KEY_FILE"] {
        command.env_remove(name);
    }
    command.output().unwrap()
}

fn fixture() -> Fixture {
    let dir = project();
    let alice = key(dir.path(), "alice.key");
    write_access(
        dir.path(),
        &access_text(&[("alice", "dev", &alice.recipient)]),
    );
    std::fs::write(
        dir.path().join(".yett/secrets.dev.enc.yaml"),
        yett::sops::encrypt_yaml(DOC, &alice.recipient).unwrap(),
    )
    .unwrap();
    std::fs::write(dir.path().join(".env.refs"), ENV_REFS).unwrap();

    let sync = yett(
        dir.path(),
        &["--identity", alice.path.to_str().unwrap(), "access", "sync"],
    );
    assert_eq!(sync.status.code(), Some(0), "{}", stderr(&sync));

    Fixture { dir, alice }
}

impl Fixture {
    fn check(&self, extra: &[&str]) -> Output {
        let mut args = vec!["--identity", self.alice.path.to_str().unwrap(), "check"];
        args.extend_from_slice(extra);
        yett(self.dir.path(), &args)
    }

    fn write(&self, name: &str, text: &str) {
        std::fs::write(self.dir.path().join(name), text).unwrap();
    }
}

#[test]
fn a_green_project_is_silent_and_exits_zero() {
    let f = fixture();

    let out = f.check(&[]);

    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(out.stdout, b"", "{}", String::from_utf8_lossy(&out.stdout));
    assert_eq!(stderr(&out), "");
}

#[test]
fn a_hand_edited_sops_config_exits_four() {
    let f = fixture();
    let config = std::fs::read_to_string(f.dir.path().join(".sops.yaml")).unwrap();
    f.write(".sops.yaml", &format!("{config}# hand edit\n"));

    let out = f.check(&[]);

    assert_eq!(out.status.code(), Some(4), "{}", stderr(&out));
    assert!(
        stderr(&out).contains(".sops.yaml does not match"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_recipient_the_access_list_does_not_know_exits_four() {
    let f = fixture();
    let bob = key(f.dir.path(), "bob.key");
    std::fs::write(
        f.dir.path().join(".yett/secrets.dev.enc.yaml"),
        yett::sops::encrypt_yaml(DOC, &bob.recipient).unwrap(),
    )
    .unwrap();

    let out = f.check(&[]);

    assert_eq!(out.status.code(), Some(4), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("do not match the access list"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn an_unresolved_reference_exits_three() {
    let f = fixture();
    f.write(
        ".env.refs",
        "DATABASE_PASSWORD=ref+sops://.yett/secrets.dev.enc.yaml#/db/nope\n",
    );

    let out = f.check(&[]);

    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    assert!(stderr(&out).contains("/db/nope"), "{}", stderr(&out));
    assert!(!stderr(&out).contains("hunter2"), "{}", stderr(&out));
}

#[test]
fn a_malformed_env_file_exits_one() {
    let f = fixture();
    f.write(".env.refs", "DATABASE_PASSWORD\n");

    let out = f.check(&[]);

    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("expected KEY=VALUE"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_missing_env_file_exits_one() {
    let f = fixture();
    std::fs::remove_file(f.dir.path().join(".env.refs")).unwrap();

    let out = f.check(&[]);

    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("cannot read"), "{}", stderr(&out));
}

#[test]
fn the_env_file_flag_picks_another_file() {
    let f = fixture();
    f.write("ci.env.refs", ENV_REFS);
    f.write(".env.refs", "BROKEN\n");

    let out = f.check(&["--env-file", "ci.env.refs"]);

    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
}
