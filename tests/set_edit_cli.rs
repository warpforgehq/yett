mod common;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use common::{access_text, key, project, stderr, write_access, Key};

const DOC: &str = concat!(
    "db:\n",
    "    password: hunter2\n",
    "    port: 5432\n",
    "stripe:\n",
    "    api_key: sk_live_42\n",
);

struct Fixture {
    dir: tempfile::TempDir,
    key: Key,
    secrets: PathBuf,
}

fn fixture() -> Fixture {
    let dir = project();
    let key = key(dir.path(), "dev.key");
    let secrets = dir.path().join(".yett/secrets.dev.enc.yaml");
    std::fs::write(
        &secrets,
        yett::sops::encrypt_yaml(DOC, &key.recipient).unwrap(),
    )
    .unwrap();
    Fixture { dir, key, secrets }
}

fn empty_fixture() -> Fixture {
    let f = fixture();
    std::fs::remove_file(&f.secrets).unwrap();
    f
}

fn sops_decrypt(f: &Fixture) -> Option<Output> {
    let mut command = Command::new("sops");
    command
        .current_dir(f.dir.path())
        .args(["--decrypt", ".yett/secrets.dev.enc.yaml"])
        .env_remove("SOPS_AGE_KEY")
        .env("SOPS_AGE_KEY_FILE", &f.key.path);
    match command.output() {
        Ok(out) => Some(out),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => panic!("cannot spawn sops: {error}"),
    }
}

fn command(dir: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_yett"));
    command.current_dir(dir).args(args);
    for name in ["YETT_IDENTITY", "ROPS_AGE", "ROPS_AGE_KEY_FILE", "EDITOR"] {
        command.env_remove(name);
    }
    command
}

impl Fixture {
    fn identity(&self) -> &str {
        self.key.path.to_str().unwrap()
    }

    fn set(&self, pointer: &str, value: &[u8]) -> Output {
        let mut child = command(
            self.dir.path(),
            &["--identity", self.identity(), "set", "dev", pointer],
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
        child.stdin.take().unwrap().write_all(value).unwrap();
        child.wait_with_output().unwrap()
    }

    fn get(&self, fragment: &str) -> Output {
        let reference = format!("ref+sops://.yett/secrets.dev.enc.yaml{fragment}");
        command(
            self.dir.path(),
            &["--identity", self.identity(), "get", &reference],
        )
        .output()
        .unwrap()
    }

    fn value(&self, fragment: &str) -> String {
        let out = self.get(fragment);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn ciphertext(&self) -> String {
        std::fs::read_to_string(&self.secrets).unwrap()
    }
}

fn recipients(ciphertext: &str) -> Vec<String> {
    let yaml: serde_yaml::Value = serde_yaml::from_str(ciphertext).unwrap();
    let mut found: Vec<String> = yaml["sops"]["age"]
        .as_sequence()
        .unwrap()
        .iter()
        .map(|entry| entry["recipient"].as_str().unwrap().to_string())
        .collect();
    found.sort();
    found
}

#[test]
fn set_replaces_one_value_and_leaves_the_rest_alone() {
    let f = fixture();
    let before = f.ciphertext();

    let out = f.set("/db/password", b"new-secret\n");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(out.stdout, b"");

    let after = f.ciphertext();
    assert_ne!(after, before, "the ciphertext must be rewritten");
    assert_eq!(
        recipients(&after),
        recipients(&before),
        "set must not change the recipients"
    );
    assert!(!after.contains("new-secret"), "{after}");

    assert_eq!(f.value("#/db/password"), "new-secret\n");
    assert_eq!(f.value("#/db/port"), "5432\n");
    assert_eq!(f.value("#/stripe/api_key"), "sk_live_42\n");
}

#[test]
fn set_creates_the_mappings_the_pointer_walks_through() {
    let f = fixture();

    let out = f.set("/queue/redis/url", b"redis://localhost:6379\n");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));

    assert_eq!(f.value("#/queue/redis/url"), "redis://localhost:6379\n");
    assert_eq!(f.value("#/db/password"), "hunter2\n");
}

#[test]
fn only_one_trailing_newline_is_stripped() {
    let f = fixture();

    let out = f.set("/db/password", b"line one\nline two\n");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(f.value("#/db/password"), "line one\nline two\n");

    let out = f.set("/db/password", b"trailing\n\n");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(f.value("#/db/password"), "trailing\n\n");
}

#[test]
fn an_empty_value_exits_one_and_leaves_the_file_untouched() {
    let f = fixture();
    let before = f.ciphertext();

    for value in [&b""[..], &b"\n"[..]] {
        let out = f.set("/db/password", value);
        assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
        assert!(stderr(&out).starts_with("yett: "), "{}", stderr(&out));
        assert_eq!(f.ciphertext(), before, "{value:?}");
    }
    assert_eq!(f.value("#/db/password"), "hunter2\n");
}

#[test]
fn a_pointer_through_a_scalar_exits_one_and_leaves_the_file_untouched() {
    let f = fixture();
    let before = f.ciphertext();

    let out = f.set("/db/password/deeper", b"nope\n");

    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("/db/password"), "{}", stderr(&out));
    assert!(!stderr(&out).contains("hunter2"), "{}", stderr(&out));
    assert_eq!(f.ciphertext(), before);
}

#[test]
fn a_pointer_that_names_no_key_exits_one() {
    let f = fixture();
    for pointer in ["", "db/password/~2"] {
        let out = f.set(pointer, b"nope\n");
        assert_eq!(out.status.code(), Some(1), "{pointer:?}: {}", stderr(&out));
    }
}

#[test]
fn edit_without_an_editor_exits_one() {
    let f = fixture();
    let before = f.ciphertext();

    let out = command(f.dir.path(), &["--identity", f.identity(), "edit", "dev"])
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("EDITOR"), "{}", stderr(&out));
    assert_eq!(f.ciphertext(), before);
}

#[test]
fn edit_re_encrypts_what_the_editor_wrote() {
    if !Path::new("/dev/shm").is_dir() {
        println!("skipped: no /dev/shm on this host");
        return;
    }
    let f = fixture();
    let before = f.ciphertext();

    let script = f.dir.path().join("editor.sh");
    std::fs::write(
        &script,
        "#!/bin/sh\nprintf 'db:\\n    password: edited\\n' > \"$1\"\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    let out = command(f.dir.path(), &["--identity", f.identity(), "edit", "dev"])
        .env("EDITOR", &script)
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let after = f.ciphertext();
    assert_ne!(after, before);
    assert_eq!(recipients(&after), recipients(&before));
    assert!(!after.contains("edited"), "{after}");
    assert_eq!(f.value("#/db/password"), "edited\n");
}

#[test]
fn edit_rejects_what_the_editor_broke() {
    if !Path::new("/dev/shm").is_dir() {
        println!("skipped: no /dev/shm on this host");
        return;
    }
    let f = fixture();
    let before = f.ciphertext();

    let script = f.dir.path().join("editor.sh");
    std::fs::write(&script, "#!/bin/sh\nprintf 'a: [1,\\n' > \"$1\"\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    let out = command(f.dir.path(), &["--identity", f.identity(), "edit", "dev"])
        .env("EDITOR", &script)
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(f.ciphertext(), before);
}

#[test]
fn an_unknown_tier_exits_one() {
    let f = fixture();
    let out = f_set_tier(&f, "staging");
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));

    let out = f_set_tier(&f, "../escape");
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
}

fn f_set_tier(f: &Fixture, tier: &str) -> Output {
    let mut child = command(
        f.dir.path(),
        &["--identity", f.identity(), "set", tier, "/db/password"],
    )
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap();
    child.stdin.take().unwrap().write_all(b"x\n").unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn set_creates_a_missing_tier_file_from_the_access_list() {
    let f = empty_fixture();
    let access = access_text(&[("ephor", "dev", &f.key.recipient)]);
    write_access(f.dir.path(), &access);

    let out = f.set("/db/password", b"hunter2\n");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(f.value("#/db/password"), "hunter2\n");

    match sops_decrypt(&f) {
        Some(out) => {
            assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
            assert!(String::from_utf8_lossy(&out.stdout).contains("hunter2"));
        }
        None => println!("skipped: the sops binary is not on PATH"),
    }

    let out = f.set("/stripe/api_key", b"sk_live_42\n");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(f.value("#/db/password"), "hunter2\n");
    assert_eq!(f.value("#/stripe/api_key"), "sk_live_42\n");
}

#[test]
fn set_on_a_missing_file_with_no_recipients_exits_one_and_writes_nothing() {
    let f = empty_fixture();
    write_access(f.dir.path(), "version: 1\npeople: []\n");

    let out = f.set("/db/password", b"hunter2\n");
    let text = stderr(&out);
    assert_eq!(out.status.code(), Some(1), "{text}");
    assert!(text.contains("yett access add"), "{text}");
    assert!(text.contains("yett access sync"), "{text}");
    assert!(!f.secrets.exists());
}

#[test]
fn set_on_a_missing_file_without_an_access_list_exits_one() {
    let f = empty_fixture();
    let out = f.set("/db/password", b"hunter2\n");
    let text = stderr(&out);
    assert_eq!(out.status.code(), Some(1), "{text}");
    assert!(text.contains("yett access add"), "{text}");
    assert!(!f.secrets.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn an_interrupted_edit_cleans_the_ram_workspace_and_reports_128_plus_signal() {
    if !Path::new("/dev/shm").is_dir() {
        eprintln!("skipped: no /dev/shm on this host");
        return;
    }
    use std::os::unix::fs::PermissionsExt;

    for (signal, expected) in [("INT", 130), ("TERM", 143)] {
        let f = fixture();
        let editor = f.dir.path().join("editor.sh");
        std::fs::write(&editor, "#!/bin/sh\nsleep 30\n").unwrap();
        std::fs::set_permissions(&editor, std::fs::Permissions::from_mode(0o755)).unwrap();

        let mut child = command(f.dir.path(), &["--identity", f.identity(), "edit", "dev"])
            .env("EDITOR", &editor)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let yett_pid = child.id();
        let prefix = format!("yett-{yett_pid}-");
        let workspace_exists = || {
            std::fs::read_dir("/dev/shm").unwrap().any(|entry| {
                entry
                    .map(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
                    .unwrap_or(false)
            })
        };

        let mut appeared = false;
        for _ in 0..150 {
            if workspace_exists() {
                appeared = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(appeared, "the workspace never appeared for SIG{signal}");

        let killed = std::process::Command::new("kill")
            .args([format!("-{signal}"), yett_pid.to_string()])
            .status()
            .unwrap();
        assert!(killed.success(), "cannot signal {signal}");

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if std::time::Instant::now() > deadline {
                let _ = child.kill();
                panic!("yett did not exit within 5s of SIG{signal}");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        assert_eq!(status.code(), Some(expected), "SIG{signal}");
        assert!(!workspace_exists(), "a yett workspace survived SIG{signal}");
    }
}
