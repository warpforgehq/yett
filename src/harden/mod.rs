mod locked;
mod process;
mod resolved;
#[cfg(test)]
mod tests;

pub use locked::{PageLocks, SecretBuf};
pub use process::harden_process;
pub use resolved::ResolvedSecret;

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Backend {
    MemfdSecret,
    MlockedHeap,
    Empty,
}

pub(crate) fn page_size() -> usize {
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if size <= 0 {
        4096
    } else {
        size as usize
    }
}

pub(crate) fn align_down(addr: usize, page: usize) -> usize {
    addr & !(page - 1)
}

pub(crate) fn align_up(addr: usize, page: usize) -> usize {
    align_down(addr.saturating_add(page - 1), page)
}

pub(crate) fn merge_pages(raw: &[(usize, usize)], page: usize) -> Vec<(usize, usize)> {
    let mut ranges: Vec<(usize, usize)> = raw
        .iter()
        .filter(|(_, len)| *len > 0)
        .map(|(addr, len)| {
            (
                align_down(*addr, page),
                align_up(addr.saturating_add(*len), page),
            )
        })
        .collect();
    ranges.sort_unstable();

    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1 => {
                if end > last.1 {
                    last.1 = end;
                }
            }
            _ => merged.push((start, end)),
        }
    }
    merged
}
