use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

static PTY_WORKED: AtomicBool = AtomicBool::new(false);

fn pty_unavailable(context: &str, error: &std::io::Error) -> Option<Session> {
    if PTY_WORKED.load(Ordering::SeqCst) {
        panic!("pty creation failed after an earlier session succeeded: {context}: {error}");
    }
    eprintln!("skipped: cannot create a pty ({context}): {error}");
    None
}

const EXPECT_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
const PRIME_DELAY: Duration = Duration::from_millis(100);

pub struct Spawn {
    dir: PathBuf,
    home: PathBuf,
    args: Vec<String>,
    prime: Option<Vec<u8>>,
    timeout: Duration,
}

impl Spawn {
    pub fn new(dir: &Path, args: &[&str]) -> Self {
        Self {
            dir: dir.to_path_buf(),
            home: dir.to_path_buf(),
            args: args.iter().map(|arg| (*arg).to_string()).collect(),
            prime: None,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    pub fn home(mut self, home: &Path) -> Self {
        self.home = home.to_path_buf();
        self
    }

    pub fn prime(mut self, bytes: &str) -> Self {
        self.prime = Some(bytes.as_bytes().to_vec());
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn spawn(self) -> Option<Session> {
        Session::open(self)
    }
}

pub struct Session {
    master: RawFd,
    child: Child,
    buffer: Arc<Mutex<String>>,
    reader: Option<JoinHandle<()>>,
    timeout: Duration,
    timed_out: bool,
}

impl Session {
    fn open(spec: Spawn) -> Option<Session> {
        let mut master: RawFd = -1;
        let mut slave: RawFd = -1;
        let rc = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if rc != 0 {
            return pty_unavailable("openpty", &std::io::Error::last_os_error());
        }

        let mut command = Command::new(env!("CARGO_BIN_EXE_yett"));
        command.current_dir(&spec.dir).args(&spec.args);
        command
            .env("XDG_CONFIG_HOME", &spec.home)
            .env("HOME", &spec.home);
        for name in ["YETT_IDENTITY", "ROPS_AGE", "ROPS_AGE_KEY_FILE", "EDITOR"] {
            command.env_remove(name);
        }
        let stdin_fd = unsafe { libc::dup(slave) };
        let stdout_fd = unsafe { libc::dup(slave) };
        let stderr_fd = unsafe { libc::dup(slave) };
        if stdin_fd < 0 || stdout_fd < 0 || stderr_fd < 0 {
            for fd in [stdin_fd, stdout_fd, stderr_fd] {
                if fd >= 0 {
                    unsafe {
                        libc::close(fd);
                    }
                }
            }
            unsafe {
                libc::close(master);
                libc::close(slave);
            }
            return pty_unavailable("dup", &std::io::Error::last_os_error());
        }
        PTY_WORKED.store(true, Ordering::SeqCst);
        command.stdin(unsafe { Stdio::from_raw_fd(stdin_fd) });
        command.stdout(unsafe { Stdio::from_raw_fd(stdout_fd) });
        command.stderr(unsafe { Stdio::from_raw_fd(stderr_fd) });
        unsafe {
            command.pre_exec(move || {
                libc::setsid();
                if libc::ioctl(slave, libc::TIOCSCTTY as _, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().expect("spawn under a pty");
        unsafe {
            libc::close(slave);
        }

        let buffer = Arc::new(Mutex::new(String::new()));
        let sink = Arc::clone(&buffer);
        let reader = std::thread::spawn(move || {
            let mut bytes = [0u8; 4096];
            loop {
                let read = unsafe { libc::read(master, bytes.as_mut_ptr().cast(), bytes.len()) };
                if read > 0 {
                    sink.lock()
                        .unwrap()
                        .push_str(&String::from_utf8_lossy(&bytes[..read as usize]));
                    continue;
                }
                if read < 0
                    && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                {
                    continue;
                }
                break;
            }
        });

        let session = Session {
            master,
            child,
            buffer,
            reader: Some(reader),
            timeout: spec.timeout,
            timed_out: false,
        };

        if let Some(prime) = spec.prime.as_deref() {
            std::thread::sleep(PRIME_DELAY);
            session.send_bytes(prime);
        }

        Some(session)
    }

    pub fn send(&self, text: &str) {
        self.send_bytes(text.as_bytes());
    }

    fn send_bytes(&self, bytes: &[u8]) {
        let mut written = 0;
        while written < bytes.len() {
            let count = unsafe {
                libc::write(
                    self.master,
                    bytes[written..].as_ptr().cast(),
                    bytes.len() - written,
                )
            };
            assert!(count > 0, "pty write: {}", std::io::Error::last_os_error());
            written += count as usize;
        }
    }

    pub fn expect(&self, needle: &str) {
        let deadline = Instant::now() + EXPECT_TIMEOUT;
        loop {
            if self.transcript().contains(needle) {
                return;
            }
            let seen = self.transcript();
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {needle:?}; saw: {seen}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn answer(&self, needle: &str, reply: &str) {
        self.expect(needle);
        self.send(reply);
    }

    pub fn transcript(&self) -> String {
        self.buffer.lock().unwrap().clone()
    }

    fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + self.timeout;
        loop {
            if let Some(status) = self.child.try_wait().expect("wait for the child") {
                return status;
            }
            if Instant::now() >= deadline {
                self.timed_out = true;
                let pid = self.child.id() as libc::pid_t;
                unsafe {
                    libc::kill(-pid, libc::SIGKILL);
                }
                let _ = self.child.kill();
                return self.child.wait().expect("reap the child");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn finish(mut self) -> (String, ExitStatus) {
        let status = self.wait();
        unsafe {
            libc::close(self.master);
        }
        if let Some(reader) = self.reader.take() {
            if self.timed_out {
                drop(reader);
            } else {
                let _ = reader.join();
            }
        }
        let text = self.transcript();
        (text, status)
    }
}
