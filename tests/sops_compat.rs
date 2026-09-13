mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::{key, stderr, Key};

const FLAT: &str = concat!("DATABASE_PASSWORD: hunter2\n", "STRIPE_KEY: sk_live_42\n");

const NESTED: &str = concat!(
    "db:\n",
    "    password: hunter2\n",
    "    port: 5432\n",
    "stripe:\n",
    "    api_key: sk_live_42\n",
);

const ENV_REFS: &str = concat!(
    "DATABASE_PASSWORD=ref+sops://secrets.dev.enc.yaml#/DATABASE_PASSWORD\n",
    "STRIPE_KEY=ref+sops://secrets.dev.enc.yaml#/STRIPE_KEY\n",
);

const PRINT_BOTH: &str = "printenv DATABASE_PASSWORD; printenv STRIPE_KEY";

const SECRETS: &str = "secrets.dev.enc.yaml";

const INHERITED: &[&str] = &[
    "SOPS_AGE_KEY",
    "SOPS_AGE_KEY_FILE",
    "ROPS_AGE",
    "ROPS_AGE_KEY_FILE",
    "YETT_IDENTITY",
    "DATABASE_PASSWORD",
    "STRIPE_KEY",
];

struct Fixture {
    dir: tempfile::TempDir,
    key: Key,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let key = key(dir.path(), "dev.key");
    Fixture { dir, key }
}

impl Fixture {
    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn identity(&self) -> &str {
        self.key.path.to_str().unwrap()
    }

    fn write(&self, name: &str, text: &str) -> PathBuf {
        let path = self.path().join(name);
        std::fs::write(&path, text).unwrap();
        path
    }

    fn write_with_yett(&self, name: &str, plaintext: &str) {
        let ciphertext = yett::sops::encrypt_yaml(plaintext, &self.key.recipient).unwrap();
        assert!(!ciphertext.contains("hunter2"), "{ciphertext}");
        self.write(name, &ciphertext);
    }

    fn write_with_sops(&self, name: &str, plaintext: &str) {
        self.write("plain.yaml", plaintext);
        let out = sops(
            self,
            &[
                "--encrypt",
                "--age",
                &self.key.recipient,
                "--input-type",
                "yaml",
                "--output-type",
                "yaml",
                "plain.yaml",
            ],
        );
        std::fs::remove_file(self.path().join("plain.yaml")).unwrap();
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        let ciphertext = String::from_utf8(out.stdout).unwrap();
        assert!(!ciphertext.contains("hunter2"), "{ciphertext}");
        self.write(name, &ciphertext);
    }
}

fn sops_probe(f: &Fixture) -> bool {
    let mut command = Command::new("sops");
    command.current_dir(f.path()).arg("--version");
    match command.output() {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            println!("skipped: the sops binary is not on PATH");
            false
        }
        Err(error) => panic!("cannot spawn sops: {error}"),
    }
}

fn sops(f: &Fixture, args: &[&str]) -> Output {
    let mut command = Command::new("sops");
    command.current_dir(f.path()).args(args);
    for name in INHERITED {
        command.env_remove(name);
    }
    command.env("SOPS_AGE_KEY_FILE", &f.key.path);
    command
        .output()
        .unwrap_or_else(|error| panic!("sops became unavailable mid-test: {error}"))
}

fn yett(f: &Fixture, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_yett"));
    command.current_dir(f.path()).args(args);
    for name in INHERITED {
        command.env_remove(name);
    }
    spawn(command, "yett").unwrap()
}

fn spawn(mut command: Command, name: &str) -> Option<Output> {
    match command.output() {
        Ok(output) => Some(output),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            println!("skipped: the {name} binary is not on PATH");
            None
        }
        Err(error) => panic!("cannot spawn {name}: {error}"),
    }
}

fn yaml(text: &str) -> serde_yaml::Value {
    serde_yaml::from_str(text).unwrap()
}

fn sorted(out: &Output) -> Vec<String> {
    let mut lines: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .collect();
    lines.sort();
    lines
}

#[test]
fn sops_decrypts_what_yett_wrote() {
    let f = fixture();
    if !sops_probe(&f) {
        return;
    }
    for (label, plaintext) in [("flat", FLAT), ("nested", NESTED)] {
        f.write_with_yett(SECRETS, plaintext);

        let out = sops(&f, &["--decrypt", SECRETS]);

        assert_eq!(out.status.code(), Some(0), "{label}: {}", stderr(&out));
        let decrypted = String::from_utf8(out.stdout).unwrap();
        assert_eq!(yaml(&decrypted), yaml(plaintext), "{label}: {decrypted}");
    }
}

#[test]
fn yett_reads_what_sops_wrote() {
    let f = fixture();
    if !sops_probe(&f) {
        return;
    }
    let cases: &[(&str, &str, &str, &str)] = &[
        ("flat", FLAT, "/DATABASE_PASSWORD", "hunter2"),
        ("flat", FLAT, "/STRIPE_KEY", "sk_live_42"),
        ("nested", NESTED, "/db/password", "hunter2"),
        ("nested", NESTED, "/db/port", "5432"),
        ("nested", NESTED, "/stripe/api_key", "sk_live_42"),
    ];

    for (label, plaintext, pointer, want) in cases {
        f.write_with_sops(SECRETS, plaintext);

        let reference = format!("ref+sops://{SECRETS}#{pointer}");
        let out = yett(&f, &["--identity", f.identity(), "get", &reference]);

        assert_eq!(
            out.status.code(),
            Some(0),
            "{label} {pointer}: {}",
            stderr(&out)
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            format!("{want}\n"),
            "{label} {pointer}"
        );
    }
}

#[test]
fn a_flat_document_injects_the_same_environment_through_both_tools() {
    let f = fixture();
    if !sops_probe(&f) {
        return;
    }
    f.write_with_yett(SECRETS, FLAT);
    f.write(".env.refs", ENV_REFS);

    let through_sops = sops(&f, &["exec-env", SECRETS, PRINT_BOTH]);
    assert_eq!(
        through_sops.status.code(),
        Some(0),
        "{}",
        stderr(&through_sops)
    );

    let through_yett = yett(
        &f,
        &[
            "--identity",
            f.identity(),
            "run",
            "--",
            "sh",
            "-c",
            PRINT_BOTH,
        ],
    );
    assert_eq!(
        through_yett.status.code(),
        Some(0),
        "{}",
        stderr(&through_yett)
    );

    assert_eq!(sorted(&through_yett), sorted(&through_sops));
    assert_eq!(sorted(&through_yett), vec!["hunter2", "sk_live_42"]);
}

#[test]
fn a_project_sops_config_does_not_break_the_documented_encrypt_flow() {
    use std::io::Write;
    use std::process::Stdio;

    let f = fixture();
    if !sops_probe(&f) {
        return;
    }
    std::fs::create_dir(f.path().join(".yett")).unwrap();
    let config = format!(
        "# generated by yett — edit secrets-access.yaml instead\ncreation_rules:\n  - path_regex: \\.yett/secrets\\.dev\\.enc\\.yaml$\n    key_groups: [{{ age: [{}] }}]\n",
        f.key.recipient
    );
    f.write(".sops.yaml", &config);

    let mut command = Command::new("sops");
    command
        .current_dir(f.path())
        .args([
            "--config",
            "/dev/null",
            "--encrypt",
            "--age",
            &f.key.recipient,
            "--input-type",
            "yaml",
            "--output-type",
            "yaml",
            "/dev/stdin",
        ])
        .env("SOPS_AGE_KEY_FILE", &f.key.path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"db:\n    password: hunter2\n")
        .unwrap();
    let encrypted = child.wait_with_output().unwrap();
    assert_eq!(encrypted.status.code(), Some(0), "{}", stderr(&encrypted));
    assert!(!String::from_utf8_lossy(&encrypted.stdout).contains("hunter2"));
    std::fs::write(
        f.path().join(".yett/secrets.dev.enc.yaml"),
        &encrypted.stdout,
    )
    .unwrap();

    let decrypted = sops(&f, &["--decrypt", ".yett/secrets.dev.enc.yaml"]);
    assert_eq!(decrypted.status.code(), Some(0), "{}", stderr(&decrypted));
    assert!(String::from_utf8_lossy(&decrypted.stdout).contains("hunter2"));

    let reference = "ref+sops://.yett/secrets.dev.enc.yaml#/db/password";
    let out = yett(&f, &["--identity", f.identity(), "get", reference]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "hunter2\n");
}

#[test]
fn sops_exec_env_refuses_a_nested_document() {
    let f = fixture();
    if !sops_probe(&f) {
        return;
    }
    f.write_with_yett(SECRETS, NESTED);

    let out = sops(&f, &["exec-env", SECRETS, PRINT_BOTH]);
    assert_ne!(out.status.code(), Some(0), "{}", stderr(&out));
    let reported = format!("{}{}", String::from_utf8_lossy(&out.stdout), stderr(&out));
    assert!(reported.contains("complex value"), "{reported}");
}
