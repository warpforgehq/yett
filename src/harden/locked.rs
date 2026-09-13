use std::collections::HashMap;
use std::ffi::c_void;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex, MutexGuard};

use zeroize::Zeroize;

#[cfg(test)]
use super::Backend;
use super::{align_down, align_up, page_size};

static PAGE_REGISTRY: LazyLock<Mutex<HashMap<usize, usize>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

static LOCK_WARNED: AtomicBool = AtomicBool::new(false);

fn registry() -> MutexGuard<'static, HashMap<usize, usize>> {
    PAGE_REGISTRY.lock().unwrap_or_else(|e| e.into_inner())
}

fn warn_lock_failure() {
    if !LOCK_WARNED.swap(true, Ordering::SeqCst) {
        eprintln!(
            "yett: warning: cannot lock a secret memory region; continuing without mlock for it"
        );
    }
}

pub(crate) fn lock_span(addr: usize, len: usize) -> Vec<usize> {
    if len == 0 {
        return Vec::new();
    }
    let page = page_size();
    let mut start = align_down(addr, page);
    let end = align_up(addr.saturating_add(len), page);
    let mut acquired = Vec::new();
    let mut registry = registry();
    while start < end {
        match registry.get_mut(&start) {
            Some(count) => {
                *count += 1;
                acquired.push(start);
            }
            None => {
                if lock_page(start, page) {
                    registry.insert(start, 1);
                    acquired.push(start);
                }
            }
        }
        start += page;
    }
    acquired
}

pub(crate) fn unlock_pages(pages: &[usize]) {
    let page = page_size();
    let mut registry = registry();
    for &start in pages {
        match registry.get_mut(&start) {
            Some(count) if *count > 1 => *count -= 1,
            Some(_) => {
                registry.remove(&start);
                unlock_page(start, page);
            }
            None => {}
        }
    }
}

fn lock_page(start: usize, page: usize) -> bool {
    unsafe {
        if libc::mlock(start as *const c_void, page) != 0 {
            warn_lock_failure();
            return false;
        }
        #[cfg(target_os = "linux")]
        let _ = libc::madvise(start as *mut c_void, page, libc::MADV_DONTDUMP);
    }
    true
}

fn unlock_page(start: usize, page: usize) {
    #[cfg(test)]
    record_munlock();
    unsafe {
        #[cfg(target_os = "linux")]
        let _ = libc::madvise(start as *mut c_void, page, libc::MADV_DODUMP);
        let _ = libc::munlock(start as *const c_void, page);
    }
}

pub struct SecretBuf {
    region: Region,
}

enum Region {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Mapped {
        ptr: *mut u8,
        len: usize,
        fd: RawFd,
    },
    Heap {
        data: Vec<u8>,
        pages: Vec<usize>,
    },
}

unsafe impl Send for SecretBuf {}
unsafe impl Sync for SecretBuf {}

impl std::fmt::Debug for SecretBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretBuf(<redacted>)")
    }
}

impl SecretBuf {
    pub fn new(value: &str) -> Self {
        Self::from_bytes(value.as_bytes())
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            region: Region::allocate(bytes),
        }
    }

    pub(crate) fn from_zeroizing(mut source: zeroize::Zeroizing<Vec<u8>>) -> Self {
        let buffer = Self::from_bytes(source.as_slice());
        source.zeroize();
        buffer
    }

    pub fn as_bytes(&self) -> &[u8] {
        match &self.region {
            Region::Mapped { ptr, len, .. } => unsafe {
                std::slice::from_raw_parts(*ptr as *const u8, *len)
            },
            Region::Heap { data, .. } => data.as_slice(),
        }
    }

    pub fn as_str(&self) -> &str {
        unsafe { std::str::from_utf8_unchecked(self.as_bytes()) }
    }

    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }

    pub fn is_empty(&self) -> bool {
        self.as_bytes().is_empty()
    }
}

impl Region {
    fn allocate(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Region::Heap {
                data: Vec::new(),
                pages: Vec::new(),
            };
        }

        #[cfg(target_os = "linux")]
        if let Some((ptr, fd)) = map_secret(bytes.len()) {
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len()) };
            return Region::Mapped {
                ptr,
                len: bytes.len(),
                fd,
            };
        }

        let mut data = Vec::with_capacity(bytes.len());
        data.extend_from_slice(bytes);
        let pages = lock_span(data.as_ptr() as usize, data.len());
        Region::Heap { data, pages }
    }
}

impl Drop for SecretBuf {
    fn drop(&mut self) {
        match &mut self.region {
            Region::Mapped { ptr, len, fd } => {
                #[cfg(test)]
                record(DropStep::Wipe);
                wipe(*ptr, *len);
                #[cfg(test)]
                record(DropStep::Unmap);
                unsafe {
                    libc::munmap(*ptr as *mut c_void, *len);
                    libc::close(*fd);
                }
            }
            Region::Heap { data, pages } => {
                #[cfg(test)]
                record(DropStep::Wipe);
                data.zeroize();
                #[cfg(test)]
                record(DropStep::Unmap);
                unlock_pages(pages);
            }
        }
    }
}

fn wipe(ptr: *mut u8, len: usize) {
    if len == 0 {
        return;
    }
    unsafe { std::slice::from_raw_parts_mut(ptr, len).zeroize() };
}

#[cfg(target_os = "linux")]
fn map_secret(len: usize) -> Option<(*mut u8, RawFd)> {
    let raw = unsafe { libc::syscall(libc::SYS_memfd_secret, libc::O_CLOEXEC as libc::c_long) };
    if raw < 0 {
        return None;
    }
    let fd = raw as RawFd;

    if unsafe { libc::ftruncate(fd, len as libc::off_t) } != 0 {
        unsafe { libc::close(fd) };
        return None;
    }

    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        unsafe { libc::close(fd) };
        return None;
    }
    Some((ptr as *mut u8, fd))
}

pub struct PageLocks {
    pages: Option<Vec<usize>>,
}

impl PageLocks {
    pub fn for_mapping(map: &serde_yaml::Mapping) -> Self {
        let page = page_size();
        let mut raw = Vec::new();
        collect_mapping(map, &mut raw);
        let merged = super::merge_pages(&raw, page);
        let mut pages = Vec::new();
        for (start, end) in &merged {
            pages.extend(lock_span(*start, end - *start));
        }
        PageLocks { pages: Some(pages) }
    }

    pub(crate) fn for_bytes(value: &str) -> Self {
        if value.is_empty() {
            return PageLocks {
                pages: Some(Vec::new()),
            };
        }
        let pages = lock_span(value.as_ptr() as usize, value.len());
        PageLocks { pages: Some(pages) }
    }

    pub(crate) fn release(&mut self) {
        if let Some(pages) = self.pages.take() {
            unlock_pages(&pages);
        }
    }
}

impl Drop for PageLocks {
    fn drop(&mut self) {
        self.release();
    }
}

fn collect_mapping(map: &serde_yaml::Mapping, out: &mut Vec<(usize, usize)>) {
    for (key, value) in map {
        collect_value(key, out);
        collect_value(value, out);
    }
}

fn collect_value(value: &serde_yaml::Value, out: &mut Vec<(usize, usize)>) {
    match value {
        serde_yaml::Value::String(text) => {
            if !text.is_empty() {
                let start = text.as_ptr() as usize;
                out.push((start, text.len()));
            }
        }
        serde_yaml::Value::Sequence(items) => {
            for item in items {
                collect_value(item, out);
            }
        }
        serde_yaml::Value::Mapping(map) => collect_mapping(map, out),
        serde_yaml::Value::Tagged(tagged) => collect_value(&tagged.value, out),
        serde_yaml::Value::Null | serde_yaml::Value::Bool(_) | serde_yaml::Value::Number(_) => {}
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DropStep {
    Wipe,
    Unmap,
}

#[cfg(test)]
thread_local! {
    static DROP_LOG: std::cell::RefCell<Vec<DropStep>> =
        const { std::cell::RefCell::new(Vec::new()) };
    static MUNLOCK_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn record(step: DropStep) {
    DROP_LOG.with(|log| log.borrow_mut().push(step));
}

#[cfg(test)]
fn record_munlock() {
    MUNLOCK_CALLS.with(|calls| calls.set(calls.get() + 1));
}

#[cfg(test)]
pub(crate) fn take_drop_log() -> Vec<DropStep> {
    DROP_LOG.with(|log| std::mem::take(&mut *log.borrow_mut()))
}

#[cfg(test)]
pub(crate) fn munlock_calls() -> usize {
    MUNLOCK_CALLS.with(std::cell::Cell::get)
}

#[cfg(test)]
pub(crate) fn registry_count(page: usize) -> Option<usize> {
    registry().get(&page).copied()
}

#[cfg(test)]
impl SecretBuf {
    pub(crate) fn backend(&self) -> Backend {
        match &self.region {
            Region::Mapped { .. } => Backend::MemfdSecret,
            Region::Heap { data, .. } if data.is_empty() => Backend::Empty,
            Region::Heap { .. } => Backend::MlockedHeap,
        }
    }

    pub(crate) fn raw_fd(&self) -> Option<RawFd> {
        match &self.region {
            Region::Mapped { fd, .. } => Some(*fd),
            Region::Heap { .. } => None,
        }
    }

    pub(crate) fn wipe_in_place(&mut self) {
        match &mut self.region {
            Region::Mapped { ptr, len, .. } => wipe(*ptr, *len),
            Region::Heap { data, .. } => data.zeroize(),
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn forced_mlock(value: &str) -> Self {
        let bytes = value.as_bytes();
        let mut data = Vec::with_capacity(bytes.len());
        data.extend_from_slice(bytes);
        let pages = lock_span(data.as_ptr() as usize, data.len());
        SecretBuf {
            region: Region::Heap { data, pages },
        }
    }
}
