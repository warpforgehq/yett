mod common;

use common::*;

#[test]
fn sync_does_not_rewrite_the_access_list() {
    let dir = project();
    let alice = key(dir.path(), "alice.key");
    let list = format!(
        "# keep this comment\nversion: 1\npeople:\n  - handle: alice\n    keys:\n      dev: {}\n",
        alice.recipient
    );
    write_access(dir.path(), &list);

    let out = yett(dir.path(), &["access", "sync"]);

    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(
        std::fs::read_to_string(dir.path().join(".yett/secrets-access.yaml")).unwrap(),
        list,
        "plain sync must leave the hand-edited access list untouched"
    );
}

#[test]
fn a_recipient_shared_by_two_handles_appears_once() {
    let dir = project();
    let alice = key(dir.path(), "alice.key");
    write_access(
        dir.path(),
        &access_text(&[
            ("alice", "dev", &alice.recipient),
            ("alice-alt", "dev", &alice.recipient),
        ]),
    );
    let access =
        yett::access::AccessList::load(&dir.path().join(".yett/secrets-access.yaml")).unwrap();

    assert_eq!(access.recipients("dev").len(), 1);
    assert_eq!(
        access
            .render_sops_config()
            .matches(&alice.recipient)
            .count(),
        1
    );
}

#[test]
fn verify_ignores_tiers_without_encrypted_files() {
    let dir = project();
    let alice = key(dir.path(), "alice.key");
    write_access(
        dir.path(),
        &access_text(&[("alice", "staging", &alice.recipient)]),
    );
    let access =
        yett::access::AccessList::load(&dir.path().join(".yett/secrets-access.yaml")).unwrap();

    yett::access::verify(
        &access,
        &access.render_sops_config(),
        &dir.path().join(".yett"),
    )
    .expect("a listed tier without a file is not a mismatch");
}

#[test]
fn replacing_the_sole_recipient_rotates_and_transfers_access() {
    let dir = project();
    let alice = key(dir.path(), "alice.key");
    let bob = key(dir.path(), "bob.key");
    write_access(
        dir.path(),
        &access_text(&[("alice", "dev", &alice.recipient)]),
    );
    let secret_path = dir.path().join(".yett/secrets.dev.enc.yaml");
    std::fs::write(
        &secret_path,
        yett::sops::encrypt_yaml(PLAINTEXT, &alice.recipient).unwrap(),
    )
    .unwrap();

    write_access(
        dir.path(),
        &access_text(&[
            ("alice", "dev", &alice.recipient),
            ("bob", "dev", &bob.recipient),
        ]),
    );
    let shared = yett(
        dir.path(),
        &["--identity", alice.path.to_str().unwrap(), "access", "sync"],
    );
    assert_eq!(shared.status.code(), Some(0), "{}", stderr(&shared));

    write_access(dir.path(), &access_text(&[("bob", "dev", &bob.recipient)]));
    let outgoing = yett(
        dir.path(),
        &["--identity", alice.path.to_str().unwrap(), "access", "sync"],
    );
    assert_eq!(outgoing.status.code(), Some(1), "{}", stderr(&outgoing));
    assert!(
        stderr(&outgoing).contains("would lose access to dev"),
        "{}",
        stderr(&outgoing)
    );

    let handed_over = yett(
        dir.path(),
        &["--identity", bob.path.to_str().unwrap(), "access", "sync"],
    );
    assert_eq!(
        handed_over.status.code(),
        Some(0),
        "{}",
        stderr(&handed_over)
    );

    let after = std::fs::read_to_string(&secret_path).unwrap();
    let bob_identity =
        yett::identity::Identity::from_secret_key(&std::fs::read_to_string(&bob.path).unwrap())
            .unwrap();
    let alice_identity =
        yett::identity::Identity::from_secret_key(&std::fs::read_to_string(&alice.path).unwrap())
            .unwrap();
    assert!(yett::sops::decrypt_yaml(&after, &bob_identity).is_ok());
    assert!(yett::sops::decrypt_yaml(&after, &alice_identity).is_err());
}

#[test]
fn sync_skips_tiers_that_left_the_access_list() {
    let dir = project();
    let alice = key(dir.path(), "alice.key");
    write_access(
        dir.path(),
        &access_text(&[("alice", "dev", &alice.recipient)]),
    );
    let secret_path = dir.path().join(".yett/secrets.dev.enc.yaml");
    std::fs::write(
        &secret_path,
        yett::sops::encrypt_yaml(PLAINTEXT, &alice.recipient).unwrap(),
    )
    .unwrap();
    let before = std::fs::read_to_string(&secret_path).unwrap();

    write_access(dir.path(), "version: 1\npeople: []\n");
    let out = yett(
        dir.path(),
        &["--identity", alice.path.to_str().unwrap(), "access", "sync"],
    );

    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(
        std::fs::read_to_string(&secret_path).unwrap(),
        before,
        "a tier absent from the list must not have its recipients stripped"
    );

    let access =
        yett::access::AccessList::load(&dir.path().join(".yett/secrets-access.yaml")).unwrap();
    let error = yett::access::verify(
        &access,
        &std::fs::read_to_string(dir.path().join(".sops.yaml")).unwrap(),
        &dir.path().join(".yett"),
    )
    .unwrap_err();
    assert_eq!(error.exit_code(), 4, "{error:?}");
}

#[test]
fn an_orphan_tier_file_does_not_block_removals() {
    let dir = project();
    let alice = key(dir.path(), "alice.key");
    let bob = key(dir.path(), "bob.key");
    write_access(
        dir.path(),
        &access_text(&[
            ("alice", "dev", &alice.recipient),
            ("bob", "dev", &bob.recipient),
        ]),
    );
    let dev = dir.path().join(".yett/secrets.dev.enc.yaml");
    std::fs::write(
        &dev,
        yett::sops::encrypt_yaml(PLAINTEXT, &alice.recipient).unwrap(),
    )
    .unwrap();
    let shared = yett(
        dir.path(),
        &["--identity", alice.path.to_str().unwrap(), "access", "sync"],
    );
    assert_eq!(shared.status.code(), Some(0), "{}", stderr(&shared));
    std::fs::write(
        dir.path().join(".yett/secrets.old.enc.yaml"),
        yett::sops::encrypt_yaml(PLAINTEXT, &alice.recipient).unwrap(),
    )
    .unwrap();

    let removed = yett(
        dir.path(),
        &[
            "--identity",
            alice.path.to_str().unwrap(),
            "access",
            "remove",
            "bob",
        ],
    );

    assert_eq!(removed.status.code(), Some(0), "{}", stderr(&removed));
}

#[test]
fn a_hostile_tier_name_is_rejected() {
    let dir = project();
    let alice = key(dir.path(), "alice.key");
    let bob = key(dir.path(), "bob.key");
    write_access(
        dir.path(),
        &access_text(&[("alice", "dev", &alice.recipient)]),
    );
    std::fs::write(dir.path().join(".sops.yaml"), "sentinel\n").unwrap();

    let out = yett(
        dir.path(),
        &["access", "add", "bob", "dev|x", &bob.recipient],
    );

    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("invalid tier name"),
        "{}",
        stderr(&out)
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join(".sops.yaml")).unwrap(),
        "sentinel\n",
        "the generated config must not be rewritten on a rejected tier"
    );
}
