mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::pty::{Session, Spawn};

const ALICE_PW: &str = "alice correct horse";
const BOB_PW: &str = "bob battery staple";
const DB_URL: &str = "postgres://alice:s3cret@localhost:5432/app";
const STRIPE_KEY: &str = "sk_test_bob_stripe_9f3a";
const ACCESS: &str = ".yett/secrets-access.yaml";
const CIPHERTEXT: &str = ".yett/secrets.dev.enc.yaml";
const DB_REF: &str = "ref+sops://.yett/secrets.dev.enc.yaml#/db/url";
const STRIPE_REF: &str = "ref+sops://.yett/secrets.dev.enc.yaml#/stripe/key";

fn passphrase(session: &Session, secret: &str) {
    session.answer("passphrase for the dev identity", &format!("{secret}\n"));
}

fn read(dir: &Path, relative: &str) -> String {
    std::fs::read_to_string(dir.join(relative)).unwrap()
}

fn project_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        for entry in std::fs::read_dir(&next).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files
}

fn non_tty(dir: &Path, home: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_yett"));
    command
        .current_dir(dir)
        .args(args)
        .env("XDG_CONFIG_HOME", home)
        .env("HOME", home)
        .env_remove("YETT_IDENTITY")
        .env_remove("ROPS_AGE")
        .env_remove("ROPS_AGE_KEY_FILE");
    command.output().unwrap()
}

#[test]
fn two_developers_share_a_dev_tier_end_to_end() {
    let project = tempfile::tempdir().unwrap();
    let alice_home = tempfile::tempdir().unwrap();
    let bob_home = tempfile::tempdir().unwrap();

    let Some(init) = Spawn::new(
        project.path(),
        &["init", "--tiers", "dev", "--handle", "alice"],
    )
    .home(alice_home.path())
    .spawn() else {
        return;
    };
    passphrase(&init, ALICE_PW);
    init.answer("confirm the dev passphrase", &format!("{ALICE_PW}\n"));
    let (text, status) = init.finish();
    assert!(status.success(), "{text}");

    assert!(project.path().join(".yett").is_dir());
    assert!(project.path().join(".sops.yaml").is_file());
    assert!(project.path().join(".env.refs").is_file());
    let access = read(project.path(), ACCESS);
    assert!(access.contains("handle: alice"), "{access}");
    assert!(!access.contains("bob"), "{access}");

    let Some(set) = Spawn::new(project.path(), &["set", "dev", "/db/url"])
        .home(alice_home.path())
        .prime(&format!("{DB_URL}\n\x04"))
        .spawn()
    else {
        return;
    };
    let (text, status) = set.finish();
    assert!(status.success(), "{text}");
    assert!(project.path().join(CIPHERTEXT).is_file());

    let Some(get) = Spawn::new(project.path(), &["get", DB_REF])
        .home(alice_home.path())
        .spawn()
    else {
        return;
    };
    passphrase(&get, ALICE_PW);
    let (text, status) = get.finish();
    assert!(status.success(), "{text}");
    assert!(text.contains(DB_URL), "{text}");

    let Some(keygen) = Spawn::new(
        project.path(),
        &["keygen", "--register", "bob", "--tier", "dev"],
    )
    .home(bob_home.path())
    .spawn() else {
        return;
    };
    passphrase(&keygen, BOB_PW);
    keygen.answer("confirm the dev passphrase", &format!("{BOB_PW}\n"));
    let (text, status) = keygen.finish();
    assert!(status.success(), "{text}");
    assert!(bob_home.path().join("yett/dev.key.age").is_file());
    let access = read(project.path(), ACCESS);
    assert!(access.contains("handle: bob"), "{access}");

    let Some(before) = Spawn::new(project.path(), &["get", DB_REF])
        .home(bob_home.path())
        .spawn()
    else {
        return;
    };
    passphrase(&before, BOB_PW);
    let (text, status) = before.finish();
    assert_eq!(status.code(), Some(2), "{text}");

    let Some(sync) = Spawn::new(project.path(), &["access", "sync"])
        .home(alice_home.path())
        .spawn()
    else {
        return;
    };
    passphrase(&sync, ALICE_PW);
    let (text, status) = sync.finish();
    assert!(status.success(), "{text}");

    let Some(after) = Spawn::new(project.path(), &["get", DB_REF])
        .home(bob_home.path())
        .spawn()
    else {
        return;
    };
    passphrase(&after, BOB_PW);
    let (text, status) = after.finish();
    assert!(status.success(), "{text}");
    assert!(text.contains(DB_URL), "{text}");

    let Some(stripe) = Spawn::new(project.path(), &["set", "dev", "/stripe/key"])
        .home(bob_home.path())
        .prime(&format!("{STRIPE_KEY}\n\x04"))
        .spawn()
    else {
        return;
    };
    passphrase(&stripe, BOB_PW);
    let (text, status) = stripe.finish();
    assert!(status.success(), "{text}");

    let Some(read_stripe) = Spawn::new(project.path(), &["get", STRIPE_REF])
        .home(alice_home.path())
        .spawn()
    else {
        return;
    };
    passphrase(&read_stripe, ALICE_PW);
    let (text, status) = read_stripe.finish();
    assert!(status.success(), "{text}");
    assert!(text.contains(STRIPE_KEY), "{text}");

    let Some(remove) = Spawn::new(project.path(), &["access", "remove", "bob"])
        .home(alice_home.path())
        .spawn()
    else {
        return;
    };
    passphrase(&remove, ALICE_PW);
    let (text, status) = remove.finish();
    assert!(status.success(), "{text}");
    let access = read(project.path(), ACCESS);
    assert!(!access.contains("bob"), "{access}");

    let Some(revoked) = Spawn::new(project.path(), &["get", DB_REF])
        .home(bob_home.path())
        .spawn()
    else {
        return;
    };
    passphrase(&revoked, BOB_PW);
    let (text, status) = revoked.finish();
    assert_eq!(status.code(), Some(2), "{text}");

    let Some(still) = Spawn::new(project.path(), &["get", DB_REF])
        .home(alice_home.path())
        .spawn()
    else {
        return;
    };
    passphrase(&still, ALICE_PW);
    let (text, status) = still.finish();
    assert!(status.success(), "{text}");
    assert!(text.contains(DB_URL), "{text}");

    let ciphertext = read(project.path(), CIPHERTEXT);
    for secret in [DB_URL, STRIPE_KEY, ALICE_PW, BOB_PW] {
        assert!(!ciphertext.contains(secret), "ciphertext leaked {secret}");
    }
    for path in project_files(project.path()) {
        let bytes = std::fs::read(&path).unwrap();
        let contents = String::from_utf8_lossy(&bytes);
        for secret in [DB_URL, STRIPE_KEY, ALICE_PW, BOB_PW] {
            assert!(
                !contents.contains(secret),
                "{} leaked {secret}",
                path.display()
            );
        }
    }
}

#[test]
fn init_with_handle_refuses_multiple_tiers_without_writing() {
    let project = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();

    let out = non_tty(
        project.path(),
        home.path(),
        &["init", "--tiers", "dev,staging", "--handle", "alice"],
    );

    assert_eq!(out.status.code(), Some(1), "{:?}", out);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("exactly one tier"),
        "{:?}",
        out
    );
    assert!(!project.path().join(".yett").exists());
    assert!(!project.path().join(".sops.yaml").exists());
}

#[test]
fn init_with_handle_without_a_tty_writes_nothing() {
    let project = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();

    let out = non_tty(
        project.path(),
        home.path(),
        &["init", "--tiers", "dev", "--handle", "alice"],
    );

    assert_eq!(out.status.code(), Some(1), "{:?}", out);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("not a terminal"),
        "{:?}",
        out
    );
    assert!(!project.path().join(".yett").exists());
    assert!(!project.path().join(".sops.yaml").exists());
}

#[test]
fn keygen_register_without_an_access_list_creates_no_identity() {
    let project = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();

    let out = non_tty(
        project.path(),
        home.path(),
        &["keygen", "--register", "bob", "--tier", "dev"],
    );

    assert_eq!(out.status.code(), Some(1), "{:?}", out);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("yett init"),
        "{:?}",
        out
    );
    assert!(!home.path().join("yett/dev.key.age").exists());
    assert!(!project.path().join(".sops.yaml").exists());
}
