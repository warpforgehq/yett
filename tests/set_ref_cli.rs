mod common;

use std::io::Write;
use std::process::{Command, Output, Stdio};

use common::{access_text, key, project, stderr, write_access, Key};

struct Fixture {
    dir: tempfile::TempDir,
    key: Key,
}

fn fixture() -> Fixture {
    let dir = project();
    let key = key(dir.path(), "dev.key");
    write_access(
        dir.path(),
        &access_text(&[("ephor", "dev", &key.recipient)]),
    );
    Fixture { dir, key }
}

impl Fixture {
    fn set(&self, args: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_yett"));
        command
            .current_dir(self.dir.path())
            .arg("--identity")
            .arg(&self.key.path)
            .arg("set")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().unwrap();
        child.stdin.take().unwrap().write_all(b"secret\n").unwrap();
        child.wait_with_output().unwrap()
    }

    fn read(&self, path: &str) -> String {
        std::fs::read_to_string(self.dir.path().join(path)).unwrap()
    }

    fn secrets_exist(&self) -> bool {
        self.dir.path().join(".yett/secrets.dev.enc.yaml").exists()
    }
}

fn assert_ok(output: &Output) {
    assert_eq!(output.status.code(), Some(0), "{}", stderr(output));
}

#[test]
fn ref_creates_the_env_file_with_the_init_header() {
    let f = fixture();
    let out = f.set(&["--ref", "DATABASE_URL", "dev", "db/url"]);
    assert_ok(&out);
    assert_eq!(
        f.read(".env.refs"),
        concat!(
            "# yett environment references. Values starting with `ref+` are resolved when\n",
            "# the process starts and injected into its environment.\n",
            "# DATABASE_URL=ref+sops://.yett/secrets.dev.enc.yaml#/db/url\n",
            "DATABASE_URL=ref+sops://.yett/secrets.dev.enc.yaml#/db/url\n"
        )
    );
}

#[test]
fn ref_replaces_only_the_existing_reference_line() {
    let f = fixture();
    let path = f.dir.path().join(".env.refs");
    std::fs::write(
        &path,
        "# before\nFIRST=literal\nDATABASE_URL=ref+sops://old#/value\n\n# after\nLAST=x\n",
    )
    .unwrap();

    assert_ok(&f.set(&["--ref", "DATABASE_URL", "dev", "/db/url"]));
    assert_ok(&f.set(&["--ref", "DATABASE_URL", "dev", "/db/url"]));

    assert_eq!(
        f.read(".env.refs"),
        "# before\nFIRST=literal\nDATABASE_URL=ref+sops://.yett/secrets.dev.enc.yaml#/db/url\n\n# after\nLAST=x\n"
    );
}

#[test]
fn literal_conflict_changes_neither_file() {
    let f = fixture();
    let path = f.dir.path().join(".env.refs");
    let before = "# keep\nDATABASE_URL=postgres://literal\n";
    std::fs::write(&path, before).unwrap();

    let out = f.set(&["--ref", "DATABASE_URL", "dev", "db/url"]);

    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("literal value"), "{}", stderr(&out));
    assert_eq!(f.read(".env.refs"), before);
    assert!(!f.secrets_exist());
}

#[test]
fn invalid_reference_name_writes_nothing() {
    let f = fixture();
    let out = f.set(&["--ref", "DATABASE-URL", "dev", "db/url"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("invalid environment variable name"));
    assert!(!f.secrets_exist());
    assert!(!f.dir.path().join(".env.refs").exists());
}

#[test]
fn omitting_ref_leaves_the_env_file_byte_for_byte_unchanged() {
    let f = fixture();
    let path = f.dir.path().join(".env.refs");
    let before = b"# untouched\r\nLITERAL = value  \r\n";
    std::fs::write(&path, before).unwrap();

    assert_ok(&f.set(&["dev", "db/url"]));

    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn custom_env_file_is_honored() {
    let f = fixture();
    let custom = f.dir.path().join("config/dev.refs");
    std::fs::create_dir(custom.parent().unwrap()).unwrap();

    assert_ok(&f.set(&[
        "--env-file",
        custom.to_str().unwrap(),
        "--ref",
        "DATABASE_URL",
        "dev",
        "db/url",
    ]));

    assert!(custom.is_file());
    assert!(f
        .read("config/dev.refs")
        .contains("DATABASE_URL=ref+sops://"));
    assert!(!f.dir.path().join(".env.refs").exists());
}

#[test]
fn pointers_with_or_without_a_leading_slash_render_canonically() {
    for pointer in ["db/x", "/db/x"] {
        let f = fixture();
        assert_ok(&f.set(&["--ref", "VALUE", "dev", pointer]));
        assert!(f
            .read(".env.refs")
            .contains("VALUE=ref+sops://.yett/secrets.dev.enc.yaml#/db/x\n"));
    }
}

#[test]
fn existing_env_file_gets_an_appended_reference() {
    let f = fixture();
    let path = f.dir.path().join(".env.refs");
    std::fs::write(&path, "# keep\nOTHER=value").unwrap();
    assert_ok(&f.set(&["--ref", "VALUE", "dev", "db/x"]));
    assert_eq!(
        f.read(".env.refs"),
        "# keep\nOTHER=value\nVALUE=ref+sops://.yett/secrets.dev.enc.yaml#/db/x\n"
    );
}
