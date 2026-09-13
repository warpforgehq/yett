use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::Error;

static HARDENED: AtomicBool = AtomicBool::new(false);

pub fn harden_process() -> Result<(), Error> {
    if HARDENED.load(Ordering::SeqCst) {
        return Ok(());
    }

    set_core_limit_to_zero()?;

    #[cfg(target_os = "linux")]
    disable_dumpable();

    raise_memlock_limit();

    HARDENED.store(true, Ordering::SeqCst);
    Ok(())
}

fn set_core_limit_to_zero() -> Result<(), Error> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) };
    if rc != 0 {
        return Err(Error::Hardening(format!(
            "cannot set RLIMIT_CORE to zero: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn disable_dumpable() {
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if rc != 0 {
        eprintln!(
            "yett: warning: cannot clear the dumpable flag ({})",
            std::io::Error::last_os_error()
        );
    }
}

fn raise_memlock_limit() {
    unsafe {
        let mut limit: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) != 0 {
            return;
        }
        if limit.rlim_cur < limit.rlim_max {
            limit.rlim_cur = limit.rlim_max;
            let _ = libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit);
        }
    }
}
