use super::signal::{should_forward, SI_QUEUE, SI_USER};
use super::*;

const TARGET: &str = "/dev/shm/yett-dev.yaml";

#[test]
fn the_editor_string_keeps_its_own_arguments() {
    let path = Path::new(TARGET);
    assert_eq!(editor_argv(Some("vi"), path).unwrap(), vec!["vi", TARGET]);
    assert_eq!(
        editor_argv(Some("code --wait"), path).unwrap(),
        vec!["code", "--wait", TARGET]
    );
    assert_eq!(
        editor_argv(Some("  nvim   -u  NONE  "), path).unwrap(),
        vec!["nvim", "-u", "NONE", TARGET]
    );
}

#[test]
fn quoted_editor_words_survive_spaces() {
    let path = Path::new(TARGET);
    assert_eq!(
        editor_argv(
            Some("'/Applications/Visual Studio Code.app/bin/code' --wait"),
            path
        )
        .unwrap(),
        vec![
            "/Applications/Visual Studio Code.app/bin/code",
            "--wait",
            TARGET
        ]
    );
    assert_eq!(
        editor_argv(Some("code --user-data-dir=\"/tmp/a b\""), path).unwrap(),
        vec!["code", "--user-data-dir=/tmp/a b", TARGET]
    );
    let error = editor_argv(Some("code \"unterminated"), path).expect_err("bad quotes");
    assert!(error.to_string().contains("unterminated"), "{error}");
}

#[test]
fn tokenizer_edge_cases_follow_shell_word_rules() {
    assert_eq!(
        editor_argv(Some("''"), Path::new(TARGET)).unwrap(),
        vec!["", TARGET]
    );
    assert_eq!(
        editor_words(Some("code \"a\\\"b\"")).unwrap(),
        vec!["code", "a\"b"]
    );
    assert_eq!(
        editor_words(Some("code \"a\\\\b\"")).unwrap(),
        vec!["code", "a\\b"]
    );
    assert_eq!(
        editor_words(Some("code \"a\\qb\"")).unwrap(),
        vec!["code", "a\\qb"]
    );
    for source in ["code \\", "code \"abc\\"] {
        let error = editor_words(Some(source)).expect_err("dangling backslash");
        assert!(error.to_string().contains("dangling backslash"), "{error}");
    }
}

#[test]
fn only_self_directed_signals_are_forwarded() {
    assert!(should_forward(SI_USER));
    assert!(should_forward(SI_QUEUE));
    assert!(!should_forward(-12345));
    #[cfg(target_os = "linux")]
    {
        assert!(!should_forward(libc::SI_KERNEL));
    }
}

#[test]
fn an_unset_or_blank_editor_is_a_usage_error() {
    let path = Path::new(TARGET);
    for editor in [None, Some(""), Some("   ")] {
        let error = editor_argv(editor, path).expect_err("no editor");
        assert_eq!(error.exit_code(), 1, "{editor:?}");
        assert!(error.to_string().contains("EDITOR"), "{error}");
    }
}
