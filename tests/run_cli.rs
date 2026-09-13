use std::path::PathBuf;
use std::process::{Command, Output};

use secrecy::ExposeSecret;

const DOC: &str = concat!("db:\n", "    password: hunter2\n",);

struct Fixture {
    dir: tempfile::TempDir,
    key: PathBuf,
    secrets: PathBuf,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let key = age::x25519::Identity::generate();
    let key_path = dir.path().join("dev.key");
    std::fs::write(&key_path, key.to_string().expose_secret()).unwrap();

    let secrets = dir.path().join("secrets.dev.enc.yaml");
    std::fs::write(
        &secrets,
        yett::sops::encrypt_yaml(DOC, &key.to_public().to_string()).unwrap(),
    )
    .unwrap();

    Fixture {
        dir,
        key: key_path,
        secrets,
    }
}

impl Fixture {
    fn reference(&self, fragment: &str) -> String {
        format!("ref+sops://{}{fragment}", self.secrets.display())
    }

    fn write(&self, name: &str, text: &str) -> PathBuf {
        let path = self.dir.path().join(name);
        std::fs::write(&path, text).unwrap();
        path
    }
}

fn yett() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_yett"));
    for name in [
        "ROPS_AGE",
        "ROPS_AGE_KEY_FILE",
        "YETT_IDENTITY",
        "LOG_LEVEL",
        "DATABASE_PASSWORD",
    ] {
        command.env_remove(name);
    }
    command
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn run(args: &[&str]) -> Output {
    yett().args(args).output().unwrap()
}

#[test]
fn literal_values_pass_through() {
    let f = fixture();
    let envf = f.write(".env.refs", "LOG_LEVEL=debug\n");
    let out = run(&[
        "run",
        "--env-file",
        envf.to_str().unwrap(),
        "--",
        "printenv",
        "LOG_LEVEL",
    ]);

    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&out), "debug\n");
}

#[test]
fn references_resolve_into_the_child() {
    let f = fixture();
    let envf = f.write(
        ".env.refs",
        &format!("DATABASE_PASSWORD={}\n", f.reference("#/db/password")),
    );
    let out = run(&[
        "--identity",
        f.key.to_str().unwrap(),
        "run",
        "--env-file",
        envf.to_str().unwrap(),
        "--",
        "printenv",
        "DATABASE_PASSWORD",
    ]);

    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&out), "hunter2\n");
}

#[test]
fn the_parent_environment_wins_and_the_reference_is_never_resolved() {
    let f = fixture();
    let missing = f.dir.path().join("secrets.prod.enc.yaml");
    let envf = f.write(
        ".env.refs",
        &format!(
            "DATABASE_PASSWORD=ref+sops://{}#/db/password\n",
            missing.display()
        ),
    );

    let out = yett()
        .env("DATABASE_PASSWORD", "from-parent")
        .args([
            "run",
            "--env-file",
            envf.to_str().unwrap(),
            "--",
            "printenv",
            "DATABASE_PASSWORD",
        ])
        .output()
        .unwrap();

    assert!(
        !missing.exists(),
        "the fixture must point at a missing file"
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&out), "from-parent\n");
}

#[test]
fn an_unresolved_reference_never_starts_the_command() {
    let f = fixture();
    let marker = f.dir.path().join("marker");
    let envf = f.write(
        ".env.refs",
        &format!("DATABASE_PASSWORD={}\n", f.reference("#/db/nope")),
    );
    let script = format!("touch {}", marker.display());
    let out = run(&[
        "--identity",
        f.key.to_str().unwrap(),
        "run",
        "--env-file",
        envf.to_str().unwrap(),
        "--",
        "sh",
        "-c",
        &script,
    ]);

    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    assert!(!marker.exists(), "the command ran despite the failure");
    assert_eq!(stdout(&out), "");
    assert!(stderr(&out).starts_with("yett: "), "{}", stderr(&out));
}

#[test]
fn the_child_exit_code_propagates_verbatim() {
    let f = fixture();
    let envf = f.write(".env.refs", "LOG_LEVEL=debug\n");
    let out = run(&[
        "run",
        "--env-file",
        envf.to_str().unwrap(),
        "--",
        "sh",
        "-c",
        "exit 7",
    ]);

    assert_eq!(out.status.code(), Some(7), "{}", stderr(&out));
}

#[test]
fn the_resolution_environment_never_reaches_the_child() {
    let f = fixture();
    let envf = f.write(
        ".env.refs",
        &format!("DATABASE_PASSWORD={}\n", f.reference("#/db/password")),
    );
    let out = run(&[
        "--identity",
        f.key.to_str().unwrap(),
        "run",
        "--env-file",
        envf.to_str().unwrap(),
        "--",
        "printenv",
        "ROPS_AGE",
    ]);

    assert_eq!(stdout(&out), "");
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
}

#[test]
fn the_default_env_file_is_read_from_the_child_cwd() {
    let f = fixture();
    f.write(".env.refs", "LOG_LEVEL=debug\n");

    let out = yett()
        .current_dir(f.dir.path())
        .args(["run", "--", "printenv", "LOG_LEVEL"])
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&out), "debug\n");
}

#[test]
fn a_custom_env_file_overrides_the_default() {
    let f = fixture();
    f.write(".env.refs", "LOG_LEVEL=wrong\n");
    let custom = f.write("custom.env", "LOG_LEVEL=right\n");

    let out = yett()
        .current_dir(f.dir.path())
        .args([
            "run",
            "--env-file",
            custom.to_str().unwrap(),
            "--",
            "printenv",
            "LOG_LEVEL",
        ])
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&out), "right\n");
}

#[test]
fn a_malformed_env_file_exits_one_without_starting_the_command() {
    let f = fixture();
    let marker = f.dir.path().join("marker");
    let envf = f.write(".env.refs", "A=1\nA=2\n");
    let script = format!("touch {}", marker.display());
    let out = run(&[
        "run",
        "--env-file",
        envf.to_str().unwrap(),
        "--",
        "sh",
        "-c",
        &script,
    ]);

    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(!marker.exists(), "the command ran despite the parse error");
    assert_eq!(stdout(&out), "");
    assert!(stderr(&out).starts_with("yett: "), "{}", stderr(&out));
}

#[test]
fn a_parent_rops_age_survives_resolution_and_the_real_identity_never_leaks() {
    let f = fixture();
    let envf = f.write(
        ".env.refs",
        &format!("DATABASE_PASSWORD={}\n", f.reference("#/db/password")),
    );
    let out = yett()
        .env("ROPS_AGE", "sentinel-parent-value")
        .args([
            "--identity",
            f.key.to_str().unwrap(),
            "run",
            "--env-file",
            envf.to_str().unwrap(),
            "--",
            "printenv",
            "ROPS_AGE",
        ])
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&out), "sentinel-parent-value\n");
}

#[test]
fn a_foreign_identity_exits_two() {
    let f = fixture();
    let stranger = age::x25519::Identity::generate();
    let stranger_path = f.dir.path().join("stranger.key");
    std::fs::write(&stranger_path, stranger.to_string().expose_secret()).unwrap();
    let envf = f.write(
        ".env.refs",
        &format!("DATABASE_PASSWORD={}\n", f.reference("#/db/password")),
    );

    let out = run(&[
        "--identity",
        stranger_path.to_str().unwrap(),
        "run",
        "--env-file",
        envf.to_str().unwrap(),
        "--",
        "printenv",
        "DATABASE_PASSWORD",
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
fn a_missing_default_env_file_exits_one_without_starting_the_command() {
    let f = fixture();
    let marker = f.dir.path().join("marker");
    let script = format!("touch {}", marker.display());
    let out = yett()
        .current_dir(f.dir.path())
        .args(["run", "--", "sh", "-c", &script])
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        !marker.exists(),
        "the command ran despite the missing env file"
    );
    assert_eq!(stdout(&out), "");
    assert!(stderr(&out).contains("cannot read"), "{}", stderr(&out));
}

#[test]
fn missing_command_is_a_usage_error() {
    let out = run(&["run"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("Usage:"), "{}", stderr(&out));
}
