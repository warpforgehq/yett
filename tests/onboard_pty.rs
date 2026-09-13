mod common;

use common::pty::{Session, Spawn};

fn passphrase(session: &Session, secret: &str) {
    session.answer("passphrase for the dev identity", &format!("{secret}\n"));
}

#[test]
fn init_handle_is_a_complete_first_run() {
    let dir = tempfile::tempdir().unwrap();

    let Some(init) = Spawn::new(dir.path(), &["init", "--tiers", "dev", "--handle", "you"]).spawn()
    else {
        return;
    };
    passphrase(&init, "correct horse");
    init.answer("confirm the dev passphrase", "correct horse\n");
    let (transcript, status) = init.finish();
    assert!(status.success(), "{transcript}");

    let access = std::fs::read_to_string(dir.path().join(".yett/secrets-access.yaml")).unwrap();
    assert!(access.contains("handle: you"), "{access}");
    let sops = std::fs::read_to_string(dir.path().join(".sops.yaml")).unwrap();
    assert!(sops.contains("age1"), "{sops}");

    std::fs::write(
        dir.path().join(".env.refs"),
        "DB_URL=ref+sops://.yett/secrets.dev.enc.yaml#/db/url\n",
    )
    .unwrap();

    let Some(set) = Spawn::new(dir.path(), &["set", "dev", "/db/url"])
        .prime("postgres://localhost:5432\n\x04")
        .spawn()
    else {
        return;
    };
    let (transcript, status) = set.finish();
    assert!(status.success(), "{transcript}");

    let Some(get) = Spawn::new(
        dir.path(),
        &["get", "ref+sops://.yett/secrets.dev.enc.yaml#/db/url"],
    )
    .spawn() else {
        return;
    };
    passphrase(&get, "correct horse");
    let (transcript, status) = get.finish();
    assert!(status.success(), "{transcript}");
    assert!(
        transcript.contains("postgres://localhost:5432"),
        "{transcript}"
    );

    let Some(run) = Spawn::new(dir.path(), &["run", "--", "printenv", "DB_URL"]).spawn() else {
        return;
    };
    passphrase(&run, "correct horse");
    let (transcript, status) = run.finish();
    assert!(status.success(), "{transcript}");
    assert!(
        transcript.contains("postgres://localhost:5432"),
        "{transcript}"
    );
}

#[test]
fn keygen_register_reuses_the_identity_under_a_pty() {
    let dir = tempfile::tempdir().unwrap();

    let Some(init) = Spawn::new(dir.path(), &["init"]).spawn() else {
        return;
    };
    let (transcript, status) = init.finish();
    assert!(status.success(), "{transcript}");

    let Some(first) = Spawn::new(
        dir.path(),
        &["keygen", "--tier", "dev", "--register", "you"],
    )
    .spawn() else {
        return;
    };
    passphrase(&first, "pw");
    first.answer("confirm the dev passphrase", "pw\n");
    let (first_text, status) = first.finish();
    assert!(status.success(), "{first_text}");

    let identity_path = dir.path().join("yett/dev.key.age");
    let before = std::fs::read(&identity_path).unwrap();

    let Some(second) = Spawn::new(
        dir.path(),
        &["keygen", "--tier", "dev", "--register", "you"],
    )
    .spawn() else {
        return;
    };
    passphrase(&second, "pw");
    let (second_text, status) = second.finish();
    assert!(status.success(), "{second_text}");
    assert!(
        !second_text.contains("confirm the dev passphrase"),
        "{second_text}"
    );

    assert_eq!(std::fs::read(&identity_path).unwrap(), before);
    let access = std::fs::read_to_string(dir.path().join(".yett/secrets-access.yaml")).unwrap();
    assert_eq!(access.matches("age1").count(), 1, "{access}");
}
