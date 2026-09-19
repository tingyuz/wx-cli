//! Linux `/proc/<pid>/mem`-based process memory reader.
//!
//! This module is Linux-only. It enumerates writable, anonymous regions from
//! `/proc/<pid>/maps` and reads memory via `pread` on `/proc/<pid>/mem`.
//!
//! Attaching requires the target process to be owned by the same user (with
//! `kernel.yama.ptrace_scope = 0`), or the caller to run as root /
//! `CAP_SYS_PTRACE`.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::PathBuf;

use crate::error::KeychainError;
use crate::mach_vm::reader::{MemRegion, MemoryReader};

/// `pread` on `/proc/<pid>/mem` fails if the offset is not page-aligned; every
/// region boundary in `/proc/<pid>/maps` is page-aligned, so chunk reads stay
/// aligned as long as the chunk size is a multiple of the page size.
const PROC_MEM_READ_CHUNK: usize = 256 * 1024; // 256 KiB

/// Reads memory from a running process via the procfs interface.
pub struct ProcFsReader {
    mem: File,
    maps_path: PathBuf,
}

impl ProcFsReader {
    /// Attach to a process by PID by opening `/proc/<pid>/mem`.
    pub fn attach(pid: u32) -> Result<Self, KeychainError> {
        let mem = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(format!("/proc/{pid}/mem"))?;
        Ok(Self {
            mem,
            maps_path: PathBuf::from(format!("/proc/{pid}/maps")),
        })
    }
}

impl MemoryReader for ProcFsReader {
    fn rw_regions(&self) -> Result<Vec<MemRegion>, KeychainError> {
        let maps = std::fs::read_to_string(&self.maps_path)?;
        Ok(parse_rw_regions(&maps))
    }

    fn read_bytes(&self, addr: u64, len: usize) -> Result<Vec<u8>, KeychainError> {
        let mut buf = vec![0u8; len];
        let mut total = 0usize;
        while total < len {
            let want = (len - total).min(PROC_MEM_READ_CHUNK);
            let offset = addr + total as u64;
            let n = self
                .mem
                .read_at(&mut buf[total..total + want], offset)
                .map_err(|e| {
                    KeychainError::Other(format!(
                        "pread /proc/<pid>/mem failed at 0x{offset:x} len={want}: {e}"
                    ))
                })?;
            if n == 0 {
                break;
            }
            total += n;
        }
        buf.truncate(total);
        Ok(buf)
    }
}

/// Parse writable anonymous regions out of a `/proc/<pid>/maps` dump.
///
/// File-backed mappings are skipped: `pread`ing past their EOF can fail, and
/// the `x'<key><salt>'` literals we search for live in heap memory.
fn parse_rw_regions(maps: &str) -> Vec<MemRegion> {
    let mut regions = Vec::new();
    for line in maps.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 {
            continue;
        }
        // Permissions: keep only readable+writable regions.
        if !fields[1].starts_with("rw") {
            continue;
        }
        let Some((start, end)) = fields[0].split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (u64::from_str_radix(start, 16), u64::from_str_radix(end, 16))
        else {
            continue;
        };
        if end <= start {
            continue;
        }
        // Skip file-backed mappings (`[heap]`/`[stack]`/anonymous are fine).
        let is_file_backed = fields.len() >= 6 && !fields[5].starts_with('[');
        if is_file_backed {
            continue;
        }
        regions.push(MemRegion { start, end });
    }
    regions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_anonymous_rw_maps_only() {
        let maps = "00400000-00452000 r-xp 00000000 08:01 2001       /usr/bin/wechat\n\
                    01250000-012e0000 rw-p 00000000 00:00 0          [heap]\n\
                    7f8d0000-7f8d1000 rw-p 00000000 00:00 0\n\
                    7f8d1000-7f8d2000 r--p 00000000 08:01 2002       /usr/lib/libfoo.so\n\
                    7ffd0000-7ffd1000 rw-p 00000000 00:00 0          [stack]\n";
        let regions = parse_rw_regions(maps);
        assert_eq!(regions.len(), 3);
        assert_eq!(regions[0].start, 0x01250000);
        assert_eq!(regions[0].end, 0x012e0000);
        assert_eq!(regions[1].start, 0x7f8d0000);
        assert_eq!(regions[2].start, 0x7ffd0000);
    }

    #[test]
    fn skips_readonly_and_file_backed() {
        let maps = "00400000-00452000 r-xp 00000000 08:01 2001 /usr/bin/wechat\n\
                    7f8d1000-7f8d2000 rw-p 00000000 08:01 2001 /var/lib/wechat/x.db-wal\n";
        assert!(parse_rw_regions(maps).is_empty());
    }

    #[test]
    fn ignores_malformed_lines() {
        let maps = "garbage\n\
                    rw-p\n\
                    00000000-00001000 rw-p 00000000 00:00 0\n";
        let regions = parse_rw_regions(maps);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].start, 0);
        assert_eq!(regions[0].end, 0x1000);
    }
}
