use std::path::{Path, PathBuf};

use crate::error::Error;

#[cfg(target_os = "linux")]
const SHM: &str = "/dev/shm";
#[cfg(target_os = "macos")]
const VOLUMES: &str = "/Volumes";
#[cfg(any(target_os = "macos", test))]
const RAM_SECTORS: &str = "ram://32768";

pub(super) struct Workspace {
    path: PathBuf,
    directory: Option<PathBuf>,
    device: Option<DeviceGuard>,
}

struct DeviceGuard {
    device: String,
    armed: bool,
}

impl Drop for DeviceGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = run(&detach_argv(&self.device));
        }
    }
}

impl Workspace {
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn write(&self, plaintext: &str) -> Result<(), Error> {
        std::fs::write(&self.path, plaintext)
            .map_err(|error| Error::Usage(format!("cannot fill {}: {error}", self.path.display())))
    }

    pub(super) fn read(&self) -> Result<String, Error> {
        std::fs::read_to_string(&self.path).map_err(|error| {
            Error::Usage(format!("cannot read back {}: {error}", self.path.display()))
        })
    }

    #[cfg(target_os = "linux")]
    pub(super) fn create(tier: &str) -> Result<Self, Error> {
        let directory = shm_dir(Path::new(SHM))?.join(format!("yett-{}", unique_suffix()));
        std::fs::create_dir(&directory).map_err(|error| {
            unsupported(&format!("cannot create {}: {error}", directory.display()))
        })?;
        private_mode(&directory, 0o700)?;
        let workspace = Workspace {
            path: directory.join(document_name(tier)),
            directory: Some(directory),
            device: None,
        };
        create_private(&workspace.path)?;
        Ok(workspace)
    }

    #[cfg(target_os = "macos")]
    pub(super) fn create(tier: &str) -> Result<Self, Error> {
        let attached = run(&attach_argv())?;
        let device = match parse_device(&attached) {
            Some(device) => device,
            None => {
                if let Some(token) = attached
                    .split_whitespace()
                    .find(|token| token.starts_with("/dev/"))
                {
                    let _ = run(&detach_argv(token));
                }
                return Err(unsupported(&format!(
                    "hdiutil reported no device: {attached:?}"
                )));
            }
        };
        let guard = DeviceGuard {
            device: device.clone(),
            armed: true,
        };
        let label = format!("yett-{}", unique_suffix());
        let volume = Path::new(VOLUMES).join(&label);
        let workspace = Workspace {
            path: volume.join(document_name(tier)),
            directory: None,
            device: Some(guard),
        };
        run(&erase_argv(&label, &device))?;
        create_private(&workspace.path)?;
        Ok(workspace)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub(super) fn create(_tier: &str) -> Result<Self, Error> {
        Err(unsupported("this platform has no RAM-backed path"))
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        if let Some(directory) = &self.directory {
            let _ = std::fs::remove_dir_all(directory);
        }
        drop(self.device.take());
    }
}

fn unsupported(detail: &str) -> Error {
    Error::Usage(format!(
        "`yett edit` needs a RAM-backed path and found none ({detail}); use `yett get` and `yett set` instead"
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn document_name(tier: &str) -> String {
    format!("secrets.{tier}.yaml")
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn unique_suffix() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    format!("{}-{nanos}", std::process::id())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn create_private(path: &Path) -> Result<(), Error> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map(|_file| ())
        .map_err(|error| unsupported(&format!("cannot create {}: {error}", path.display())))
}

#[cfg(target_os = "linux")]
fn private_mode(path: &Path, mode: u32) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|error| unsupported(&format!("cannot lock down {}: {error}", path.display())))
}

#[cfg(any(target_os = "linux", test))]
pub(super) fn shm_dir(candidate: &Path) -> Result<&Path, Error> {
    if !candidate.is_dir() {
        return Err(unsupported(&format!(
            "{} is not a directory",
            candidate.display()
        )));
    }
    #[cfg(target_os = "linux")]
    verify_tmpfs(candidate)?;
    Ok(candidate)
}

#[cfg(target_os = "linux")]
fn verify_tmpfs(path: &Path) -> Result<(), Error> {
    use std::os::unix::ffi::OsStrExt;

    const TMPFS_MAGIC: libc::c_long = 0x0102_1994;
    let raw = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| unsupported("the RAM path contains a NUL byte"))?;
    let mut stats: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(raw.as_ptr(), &mut stats) } != 0 {
        return Err(unsupported(&format!(
            "cannot inspect {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }
    if stats.f_type != TMPFS_MAGIC {
        return Err(unsupported(&format!(
            "{} is not a tmpfs mount",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(any(target_os = "macos", test))]
pub(super) fn attach_argv() -> Vec<String> {
    vec![
        "hdiutil".to_string(),
        "attach".to_string(),
        "-nomount".to_string(),
        RAM_SECTORS.to_string(),
    ]
}

#[cfg(any(target_os = "macos", test))]
pub(super) fn erase_argv(label: &str, device: &str) -> Vec<String> {
    vec![
        "diskutil".to_string(),
        "eraseVolume".to_string(),
        "HFS+".to_string(),
        label.to_string(),
        device.to_string(),
    ]
}

pub(super) fn detach_argv(device: &str) -> Vec<String> {
    vec![
        "hdiutil".to_string(),
        "detach".to_string(),
        device.to_string(),
    ]
}

#[cfg(any(target_os = "macos", test))]
pub(super) fn parse_device(stdout: &str) -> Option<String> {
    stdout
        .split_whitespace()
        .find(|token| token.starts_with("/dev/disk"))
        .map(str::to_string)
}

fn run(argv: &[String]) -> Result<String, Error> {
    let (program, arguments) = argv
        .split_first()
        .ok_or_else(|| unsupported("empty command"))?;
    let output = std::process::Command::new(program)
        .args(arguments)
        .output()
        .map_err(|error| unsupported(&format!("cannot run {program}: {error}")))?;
    if !output.status.success() {
        return Err(unsupported(&format!(
            "{program} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests;
