use std::sync::atomic::{AtomicI32, Ordering};

use crate::error::Error;

use super::no_editor;

pub(super) static INTERRUPTED: AtomicI32 = AtomicI32::new(0);
pub(super) static EDITOR_PID: AtomicI32 = AtomicI32::new(0);

const TERMINATION_SIGNALS: [libc::c_int; 4] =
    [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];

fn block_termination_signals() -> libc::sigset_t {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for signal in TERMINATION_SIGNALS {
            libc::sigaddset(&mut set, signal);
        }
        let mut previous: libc::sigset_t = std::mem::zeroed();
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut previous);
        previous
    }
}

fn restore_signal_mask(previous: libc::sigset_t) {
    unsafe {
        libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
    }
}

pub(super) fn spawn(argv: &[String]) -> Result<std::process::ExitStatus, Error> {
    use std::os::unix::process::CommandExt;

    let (program, arguments) = argv.split_first().ok_or_else(no_editor)?;
    let previous = block_termination_signals();
    let mut unblock: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut unblock);
        for signal in TERMINATION_SIGNALS {
            libc::sigaddset(&mut unblock, signal);
        }
    }
    let mut command = std::process::Command::new(program);
    command.args(arguments);
    unsafe {
        command.pre_exec(move || {
            libc::sigprocmask(libc::SIG_UNBLOCK, &unblock, std::ptr::null_mut());
            Ok(())
        });
    }
    let spawned = command.spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => {
            restore_signal_mask(previous);
            return Err(Error::Usage(format!("cannot run `{program}`: {error}")));
        }
    };
    EDITOR_PID.store(child.id() as i32, Ordering::SeqCst);
    restore_signal_mask(previous);
    if interrupted_signal().is_some() {
        unsafe {
            libc::kill(child.id() as libc::pid_t, libc::SIGKILL);
        }
    }

    let status = child
        .wait()
        .map_err(|error| Error::Usage(format!("cannot wait for `{program}`: {error}")));

    let previous = block_termination_signals();
    EDITOR_PID.store(0, Ordering::SeqCst);
    restore_signal_mask(previous);
    status
}

pub(super) fn interrupted_signal() -> Option<i32> {
    let signal = INTERRUPTED.load(Ordering::SeqCst);
    (signal != 0).then_some(signal)
}

#[cfg(target_os = "linux")]
pub(super) const SI_USER: libc::c_int = 0;
#[cfg(target_os = "linux")]
pub(super) const SI_QUEUE: libc::c_int = -1;
#[cfg(target_os = "macos")]
pub(super) const SI_USER: libc::c_int = 0x10001;
#[cfg(target_os = "macos")]
pub(super) const SI_QUEUE: libc::c_int = 0x10002;

pub(super) fn should_forward(si_code: libc::c_int) -> bool {
    si_code == SI_USER || si_code == SI_QUEUE
}

extern "C" fn note_interrupt(
    signal: libc::c_int,
    info: *mut libc::siginfo_t,
    _context: *mut libc::c_void,
) {
    INTERRUPTED.store(signal, Ordering::SeqCst);
    let externally_directed = unsafe {
        info.as_ref()
            .map(|info| should_forward(info.si_code))
            .unwrap_or(true)
    };
    let pid = EDITOR_PID.load(Ordering::SeqCst);
    if externally_directed && pid > 0 {
        unsafe {
            libc::kill(pid, signal);
        }
    }
}

pub(super) fn install_handlers() {
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = note_interrupt as *const () as libc::sighandler_t;
        action.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut action.sa_mask);
        for signal in TERMINATION_SIGNALS {
            libc::sigaction(signal, &action, std::ptr::null_mut());
        }
    }
}
