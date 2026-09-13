use super::locked::{self, DropStep};
use super::*;

#[test]
fn hardening_zeroes_the_core_limit() {
    harden_process().expect("hardening must succeed");
    let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) }, 0);
    assert_eq!(limit.rlim_cur, 0);
}

#[test]
fn page_math_aligns_and_dedupes() {
    let page = 4096usize;
    assert_eq!(align_down(0x1234, page), 0x1000);
    assert_eq!(align_up(0x1234, page), 0x2000);
    assert_eq!(align_down(0x2000, page), 0x2000);
    assert_eq!(align_up(0x2000, page), 0x2000);

    let raw = [(0x1000usize, 10usize), (0x1800, 10), (0x5000, 10)];
    assert_eq!(
        merge_pages(&raw, page),
        vec![(0x1000, 0x2000), (0x5000, 0x6000)]
    );
}

#[test]
fn zero_length_ranges_never_lock_a_page() {
    assert!(merge_pages(&[(0x1234, 0)], 4096).is_empty());
    assert!(merge_pages(&[], 4096).is_empty());
    assert!(merge_pages(&[(0, 0)], 4096).is_empty());
}

#[test]
fn adjacent_ranges_merge_into_one() {
    let page = 4096;
    assert_eq!(
        merge_pages(&[(0x1000, 0x1000), (0x2000, 0x500)], page),
        vec![(0x1000, 0x3000)]
    );
}

#[test]
fn a_secret_buffer_round_trips_and_wipes_in_place() {
    let mut secret = SecretBuf::new("hunter2-secret");
    assert_eq!(secret.as_str(), "hunter2-secret");
    assert_eq!(secret.as_bytes().len(), 14);
    assert_eq!(secret.len(), 14);
    assert!(!secret.is_empty());

    secret.wipe_in_place();

    assert!(secret.as_bytes().iter().all(|byte| *byte == 0));
}

#[test]
fn dropping_a_secret_buffer_closes_its_descriptor() {
    let secret = SecretBuf::new("descriptor-secret");
    let backend = secret.backend();
    let fd = secret.raw_fd();
    drop(secret);
    if let (Backend::MemfdSecret, Some(fd)) = (backend, fd) {
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
    }
}

#[test]
fn drop_wipes_before_releasing_the_region() {
    let _ = locked::take_drop_log();
    {
        let _secret = SecretBuf::new("ordering-secret");
    }
    let log = locked::take_drop_log();
    assert_eq!(
        log,
        vec![DropStep::Wipe, DropStep::Unmap],
        "the production Drop path must wipe before munmap/munlock"
    );
}

#[test]
fn owners_share_a_page_without_double_unlocking() {
    let page = page_size();
    let first = [7u8; 64];
    let addr = first.as_ptr() as usize;
    let start = align_down(addr, page);

    let owner_a = locked::lock_span(addr, first.len());
    assert_eq!(locked::registry_count(start), Some(1));

    let owner_b = locked::lock_span(addr, first.len());
    assert_eq!(locked::registry_count(start), Some(2));

    let before = locked::munlock_calls();
    locked::unlock_pages(&owner_a);
    assert_eq!(locked::registry_count(start), Some(1));
    assert_eq!(
        locked::munlock_calls(),
        before,
        "releasing one owner must not munlock a page another owner holds"
    );

    locked::unlock_pages(&owner_b);
    assert_eq!(locked::registry_count(start), None);
    assert_eq!(locked::munlock_calls(), before + 1);
}

#[test]
fn a_page_that_cannot_be_locked_is_not_counted() {
    let addr = 0x7fff_0000_0000usize;
    let acquired = locked::lock_span(addr, page_size());
    assert!(acquired.is_empty(), "mlock of an unmapped page must fail");
    assert_eq!(locked::registry_count(addr), None);
}

#[test]
fn a_secret_document_is_readable_while_locked_and_redacted() {
    use crate::identity::Identity;
    use crate::rops_bridge::EnvSandbox;
    use crate::sops::{encrypt_yaml, SecretDocument};
    use age::secrecy::ExposeSecret;

    let _env = EnvSandbox::acquire();
    let dir = tempfile::tempdir().unwrap();
    let key = age::x25519::Identity::generate();
    let identity = Identity::from_secret_key(key.to_string().expose_secret()).unwrap();
    let ciphertext = encrypt_yaml("db:\n    password: hunter2\n", &key.to_public().to_string())
        .expect("the document must encrypt");
    let path = dir.path().join("secrets.dev.enc.yaml");
    std::fs::write(&path, ciphertext).unwrap();

    let document = SecretDocument::load(&path, &identity).expect("the document must decrypt");
    let value = document
        .resolve_pointer(&["db".to_string(), "password".to_string()])
        .expect("the pointer must resolve");
    assert_eq!(value.expose_secret(), "hunter2");

    let rendered = format!("{document:?}");
    assert!(!rendered.contains("hunter2"), "{rendered}");
    assert!(rendered.contains("<redacted>"), "{rendered}");
}

#[cfg(target_os = "linux")]
#[test]
fn memfd_secret_round_trips_or_skips() {
    match memfd_probe() {
        MemfdProbe::Skip(reason) => {
            eprintln!("skipped: {reason}");
            return;
        }
        MemfdProbe::Fail(reason) => panic!("{reason}"),
        MemfdProbe::Available => {}
    }
    let secret = SecretBuf::new("round-trip-secret");
    assert_eq!(secret.backend(), Backend::MemfdSecret);
    assert_eq!(secret.as_str(), "round-trip-secret");
}

#[cfg(target_os = "linux")]
#[test]
fn locked_memory_shows_up_in_vmlck() {
    let baseline = vmlck_bytes().expect("VmLck must be readable");
    let secret = SecretBuf::forced_mlock(&"a".repeat(256 * 1024));
    let locked = vmlck_bytes().expect("VmLck must be readable");
    assert!(
        locked >= baseline + 128 * 1024,
        "baseline={baseline} locked={locked}"
    );

    drop(secret);
    let after = vmlck_bytes().expect("VmLck must be readable");
    assert!(
        after <= baseline + page_size(),
        "baseline={baseline} after={after}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn the_no_dump_flag_is_cleared_after_release() {
    let secret = SecretBuf::forced_mlock(&"b".repeat(4096));
    let addr = secret.as_bytes().as_ptr() as usize;
    let Some(locked_has_flag) = vmflags_has_dd(addr) else {
        eprintln!("skipped: /proc/self/smaps is unavailable or unparsable");
        return;
    };
    if !locked_has_flag {
        eprintln!("skipped: the page was not marked DONTDUMP (mlock unavailable?)");
        return;
    }

    drop(secret);
    match vmflags_has_dd(addr) {
        Some(false) => {}
        Some(true) => panic!("MADV_DODUMP was not applied on release"),
        None => eprintln!("skipped: the page left /proc/self/smaps before it could be checked"),
    }
}

#[cfg(target_os = "linux")]
fn vmlck_bytes() -> Option<usize> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmLck:"))?;
    let kb: usize = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kb * 1024)
}

#[cfg(target_os = "linux")]
fn vmflags_has_dd(addr: usize) -> Option<bool> {
    let smaps = std::fs::read_to_string("/proc/self/smaps").ok()?;
    let mut current: Option<(usize, usize)> = None;
    for line in smaps.lines() {
        if let Some(range) = parse_smaps_range(line) {
            current = Some(range);
            continue;
        }
        if let (Some(flags), Some((start, end))) = (line.strip_prefix("VmFlags:"), current) {
            if addr >= start && addr < end {
                return Some(flags.split_whitespace().any(|flag| flag == "dd"));
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn parse_smaps_range(line: &str) -> Option<(usize, usize)> {
    let range = line.split_whitespace().next()?;
    let (start, end) = range.split_once('-')?;
    let parse = |text: &str| usize::from_str_radix(text, 16).ok();
    Some((parse(start)?, parse(end)?))
}

#[cfg(target_os = "linux")]
enum MemfdProbe {
    Available,
    Skip(String),
    Fail(String),
}

#[cfg(target_os = "linux")]
fn memfd_probe() -> MemfdProbe {
    use std::os::unix::io::RawFd;
    let raw = unsafe { libc::syscall(libc::SYS_memfd_secret, libc::O_CLOEXEC as libc::c_long) };
    if raw >= 0 {
        unsafe { libc::close(raw as RawFd) };
        return MemfdProbe::Available;
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ENOSYS) => MemfdProbe::Skip(format!("memfd_secret unsupported: {error}")),
        Some(libc::EPERM) => {
            MemfdProbe::Skip(format!("memfd_secret blocked by seccomp/LSM: {error}"))
        }
        _ => MemfdProbe::Fail(format!("memfd_secret failed unexpectedly: {error}")),
    }
}
