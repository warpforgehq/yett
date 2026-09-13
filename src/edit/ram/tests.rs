use super::*;

#[test]
fn the_ram_disk_argv_is_built_without_running_anything() {
    assert_eq!(
        attach_argv(),
        vec!["hdiutil", "attach", "-nomount", "ram://32768"]
    );
    assert_eq!(
        erase_argv("yett-4242", "/dev/disk7"),
        vec!["diskutil", "eraseVolume", "HFS+", "yett-4242", "/dev/disk7"]
    );
    assert_eq!(
        detach_argv("/dev/disk7"),
        vec!["hdiutil", "detach", "/dev/disk7"]
    );
}

const DEVICE: &[(&str, Option<&str>)] = &[
    ("/dev/disk4          \n", Some("/dev/disk4")),
    ("/dev/disk10\n", Some("/dev/disk10")),
    (
        "/dev/disk4          \tGUID_partition_scheme\t\n",
        Some("/dev/disk4"),
    ),
    ("", None),
    ("\n", None),
    ("hdiutil: attach failed\n", None),
    ("/dev/rdisk4\n", None),
];

#[test]
fn the_attached_device_is_read_out_of_the_hdiutil_line() {
    for (stdout, want) in DEVICE {
        assert_eq!(
            parse_device(stdout).as_deref(),
            *want,
            "{:?}",
            stdout.escape_debug().to_string()
        );
    }
}

#[test]
fn a_missing_backend_points_at_get_and_set() {
    let error = shm_dir(Path::new("/nonexistent/yett/dev/shm")).expect_err("no tmpfs there");
    let text = error.to_string();
    assert_eq!(error.exit_code(), 1, "{text}");
    assert!(text.contains("yett get"), "{text}");
    assert!(text.contains("yett set"), "{text}");
    assert!(!text.contains("TMPDIR"), "{text}");
}

#[cfg(target_os = "linux")]
#[test]
fn the_workspace_file_is_gone_once_the_guard_drops() {
    if let Err(error) = shm_dir(Path::new("/dev/shm")) {
        eprintln!("skipped: {error}");
        return;
    }

    use std::os::unix::fs::PermissionsExt;
    let workspace = Workspace::create("dev").expect("tmpfs workspace");
    let path = workspace.path().to_path_buf();
    workspace.write("db:\n    password: hunter2\n").unwrap();

    assert!(path.starts_with("/dev/shm"), "{}", path.display());
    let file_mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(file_mode & 0o777, 0o600, "{file_mode:o}");
    let directory = workspace.directory.clone().expect("a workspace directory");
    let directory_mode = std::fs::metadata(&directory).unwrap().permissions().mode();
    assert_eq!(directory_mode & 0o777, 0o700, "{directory_mode:o}");

    drop(workspace);
    assert!(!path.exists(), "{} survived the guard", path.display());
    assert!(
        !directory.exists(),
        "{} survived the guard",
        directory.display()
    );
}
