mod common;

use std::process::{Command, Output};

use common::{access_text, key, project, stderr, write_access, Key};

struct Fixture {
    dir: tempfile::TempDir,
    key: Key,
}

fn fixture(source: &str) -> Fixture {
    let dir = project();
    let key = key(dir.path(), "dev.key");
    write_access(
        dir.path(),
        &access_text(&[("owner", "dev", &key.recipient)]),
    );
    std::fs::write(dir.path().join(".env.local"), source).unwrap();
    Fixture { dir, key }
}

impl Fixture {
    fn import(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_yett"))
            .current_dir(self.dir.path())
            .arg("import")
            .args(args)
            .output()
            .unwrap()
    }

    fn get(&self, key: &str) -> String {
        let output = Command::new(env!("CARGO_BIN_EXE_yett"))
            .current_dir(self.dir.path())
            .args(["--identity", self.key.path.to_str().unwrap(), "get"])
            .arg(format!("dev/{key}"))
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        String::from_utf8(output.stdout).unwrap()
    }

    fn read(&self, path: &str) -> String {
        std::fs::read_to_string(self.dir.path().join(path)).unwrap()
    }
}

fn assert_ok(output: &Output) {
    assert_eq!(output.status.code(), Some(0), "{}", stderr(output));
}

#[test]
fn imports_all_keys_and_creates_refs_with_the_header() {
    let f = fixture("DATABASE_URL=postgres://localhost\nPORT=3000\n");
    assert_ok(&f.import(&[]));
    assert_eq!(f.get("DATABASE_URL"), "postgres://localhost\n");
    assert_eq!(f.get("PORT"), "3000\n");
    assert_eq!(
        f.read(".env.local"),
        "DATABASE_URL=postgres://localhost\nPORT=3000\n"
    );
    assert_eq!(
        f.read(".env.refs"),
        concat!(
            "# yett environment references. Values starting with `ref+` are resolved when\n",
            "# the process starts and injected into its environment.\n",
            "# DATABASE_URL=ref+sops://.yett/secrets.dev.enc.yaml#/db/url\n",
            "DATABASE_URL=ref+sops://.yett/secrets.dev.enc.yaml#/DATABASE_URL\n",
            "PORT=ref+sops://.yett/secrets.dev.enc.yaml#/PORT\n"
        )
    );
}

#[test]
fn merges_in_place_and_is_idempotent() {
    let f = fixture("A=one\nB=two\n");
    std::fs::write(
        f.dir.path().join(".env.refs"),
        "# before\nA=ref+sops://old#/a\n\n# middle\nOTHER=literal\n# after\n",
    )
    .unwrap();
    assert_ok(&f.import(&[]));
    assert_ok(&f.import(&[]));
    assert_eq!(
        f.read(".env.refs"),
        concat!(
            "# before\n",
            "A=ref+sops://.yett/secrets.dev.enc.yaml#/A\n",
            "\n# middle\nOTHER=literal\n# after\n",
            "B=ref+sops://.yett/secrets.dev.enc.yaml#/B\n"
        )
    );
    assert_eq!(f.get("A"), "one\n");
    assert_eq!(f.get("B"), "two\n");
}

#[test]
fn dry_run_writes_nothing_and_exclude_omits_exact_keys() {
    let f = fixture("A=one\nAB=two\nB=three\n");
    let dry = f.import(&["--dry-run", "--exclude", "A,B"]);
    assert_ok(&dry);
    assert_eq!(
        String::from_utf8(dry.stdout).unwrap(),
        "AB=ref+sops://.yett/secrets.dev.enc.yaml#/AB\n"
    );
    assert!(!f.dir.path().join(".env.refs").exists());
    assert!(!f.dir.path().join(".yett/secrets.dev.enc.yaml").exists());
    assert_ok(&f.import(&["--exclude", "A,B"]));
    assert!(f.read(".env.refs").contains("AB=ref+sops://"));
    assert!(!f.read(".env.refs").contains("\nA=ref+sops://"));
    assert_eq!(f.get("AB"), "two\n");
}

#[test]
fn literal_conflict_is_atomic_and_force_replaces_it() {
    let f = fixture("A=changed\n");
    let refs = "# keep\nA=literal\n";
    std::fs::write(f.dir.path().join(".env.refs"), refs).unwrap();
    let output = f.import(&[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("literal value"));
    assert_eq!(f.read(".env.refs"), refs);
    assert!(!f.dir.path().join(".yett/secrets.dev.enc.yaml").exists());
    assert_ok(&f.import(&["--force"]));
    assert_eq!(
        f.read(".env.refs"),
        "# keep\nA=ref+sops://.yett/secrets.dev.enc.yaml#/A\n"
    );
    assert_eq!(f.get("A"), "changed\n");
}

#[test]
fn existing_reference_is_copied_without_encryption() {
    let f = fixture("REMOTE=ref+vault://secret/app#/token\nLOCAL=secret\n");
    assert_ok(&f.import(&[]));
    assert!(f
        .read(".env.refs")
        .contains("REMOTE=ref+vault://secret/app#/token\n"));
    assert_eq!(f.get("LOCAL"), "secret\n");
    let missing = Command::new(env!("CARGO_BIN_EXE_yett"))
        .current_dir(f.dir.path())
        .args([
            "--identity",
            f.key.path.to_str().unwrap(),
            "get",
            "dev/REMOTE",
        ])
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(3));
}

#[test]
fn quoted_values_decode_and_round_trip() {
    let f = fixture("SINGLE='plain value'\nDOUBLE=\"first\\nsecond\\t\\\"quoted\\\"\"\n");
    assert_ok(&f.import(&[]));
    assert_eq!(f.get("SINGLE"), "plain value\n");
    assert_eq!(f.get("DOUBLE"), "first\nsecond\t\"quoted\"\n");
}

#[test]
fn invalid_key_and_multiline_value_are_usage_errors() {
    for (source, line) in [
        ("OK=1\nbad-key=2\n", "line 2"),
        ("A=\"open\nB=2\n", "line 1"),
    ] {
        let f = fixture(source);
        let output = f.import(&[]);
        assert_eq!(output.status.code(), Some(1));
        assert!(stderr(&output).contains(line), "{}", stderr(&output));
        assert!(!f.dir.path().join(".env.refs").exists());
        assert!(!f.dir.path().join(".yett/secrets.dev.enc.yaml").exists());
    }
}

#[test]
fn a_tier_without_recipients_writes_nothing() {
    let f = fixture("A=secret\n");
    write_access(f.dir.path(), "version: 1\npeople: []\n");
    let output = f.import(&[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("no recipients"));
    assert!(!f.dir.path().join(".env.refs").exists());
    assert!(!f.dir.path().join(".yett/secrets.dev.enc.yaml").exists());
}
