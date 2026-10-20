// SPDX-License-Identifier: Apache-2.0
//! Experimental inherited-FD backing for read-only virtio-pmem.
//! No path reopen, read/seek, RAM CoW, allocation or SDK operation.
use std::io;

const PREFIX: &str = "aenv-pmem-fd:";
const ALIGNMENT: u64 = 2 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativePmemFd {
    fd: i32,
    bytes: u64,
}

pub fn is_native_pmem_path(path: &str) -> bool {
    path.starts_with(PREFIX)
}

impl NativePmemFd {
    /// Kept in the existing path field so ordinary snapshot schemas do not change.
    /// This process-local form is explicitly refused for snapshot/save and restore.
    pub fn parse(path: &str) -> io::Result<Option<Self>> {
        let Some(value) = path.strip_prefix(PREFIX) else {
            return Ok(None);
        };
        let parts: Vec<_> = value.split(':').collect();
        if parts.len() != 4 || parts[0] != "v1" || parts[3] != "nc" {
            return Err(invalid("expected aenv-pmem-fd:v1:FD:BYTES:nc"));
        }
        fn decimal(value: &str) -> bool {
            !value.is_empty()
                && value.bytes().all(|b| b.is_ascii_digit())
                && (value.len() == 1 || !value.starts_with('0'))
        }
        if !decimal(parts[1]) || !decimal(parts[2]) {
            return Err(invalid(
                "native FD and length must be canonical decimal integers",
            ));
        }
        let fd: i32 = parts[1].parse().map_err(|_| invalid("invalid native FD"))?;
        let bytes: u64 = parts[2]
            .parse()
            .map_err(|_| invalid("invalid native length"))?;
        if !(10..=17).contains(&fd)
            || bytes == 0
            || !bytes.is_multiple_of(ALIGNMENT)
            || bytes > isize::MAX as u64
        {
            return Err(invalid(
                "native pmem needs FD 10..17 and positive 2MiB-aligned length",
            ));
        }
        Ok(Some(Self { fd, bytes }))
    }

    #[cfg(target_os = "linux")]
    pub fn map(self, read_only: bool) -> io::Result<(std::fs::File, u64, u64, u64)> {
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::fs::FileTypeExt;
        if !read_only {
            return Err(invalid("native device pmem is read-only"));
        }
        // SAFETY: fcntl validates the source descriptor; no ownership is taken from it.
        let raw = unsafe { libc::fcntl(self.fd, libc::F_DUPFD_CLOEXEC, 256) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fcntl just returned a fresh descriptor, now owned exactly once.
        let file = unsafe { std::fs::File::from_raw_fd(raw) };
        // SAFETY: file owns a valid open descriptor for this entire operation.
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if flags & libc::O_ACCMODE != libc::O_RDONLY || flags & libc::O_SYNC != libc::O_SYNC {
            return Err(invalid("native pmem FD must retain O_RDONLY and O_SYNC"));
        }
        if !file.metadata()?.file_type().is_char_device() {
            return Err(invalid("native NC backing must be a character device"));
        }
        let length = usize::try_from(self.bytes).map_err(|_| invalid("native length overflow"))?;
        // SAFETY: a positive, checked length is mapped read-only. The kernel checks
        // device range validity. The returned mapping is owned by Pmem::drop.
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_READ,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        if pointer == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok((file, self.bytes, pointer as u64, self.bytes))
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_paths_keep_the_legacy_backend() {
        for path in ["/tmp/base.erofs", "/proc/self/fd/10", ""] {
            assert!(NativePmemFd::parse(path).unwrap().is_none());
        }
    }

    #[test]
    fn parses_reserved_descriptor_and_exact_length() {
        assert_eq!(
            NativePmemFd::parse("aenv-pmem-fd:v1:10:4194304:nc").unwrap(),
            Some(NativePmemFd {
                fd: 10,
                bytes: 4194304
            })
        );
    }

    #[test]
    fn malformed_native_forms_never_fall_back_to_file_open() {
        for path in [
            "aenv-pmem-fd:",
            "aenv-pmem-fd:v2:10:4194304:nc",
            "aenv-pmem-fd:v1:10:4194304:cc",
            "aenv-pmem-fd:v1:10:4194304:nc:extra",
            "aenv-pmem-fd:v1:+10:4194304:nc",
            "aenv-pmem-fd:v1:010:4194304:nc",
        ] {
            assert!(is_native_pmem_path(path));
            assert!(NativePmemFd::parse(path).is_err());
        }
    }

    #[test]
    fn rejects_unreserved_descriptors_and_invalid_lengths() {
        for path in [
            "aenv-pmem-fd:v1:3:4194304:nc",
            "aenv-pmem-fd:v1:18:4194304:nc",
            "aenv-pmem-fd:v1:10:0:nc",
            "aenv-pmem-fd:v1:10:4096:nc",
            "aenv-pmem-fd:v1:10:18446744073709551616:nc",
        ] {
            assert!(NativePmemFd::parse(path).is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn duplicate_preserves_flags_and_original_descriptor() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        // Local character-device fixture only; this is not UB or NC hardware proof.
        let source = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_SYNC)
            .open("/dev/zero")
            .unwrap();
        let backing = NativePmemFd {
            fd: source.as_raw_fd(),
            bytes: ALIGNMENT,
        };
        let (copy, bytes, pointer, length) = backing.map(true).unwrap();
        // SAFETY: both descriptors are owned and remain open.
        let source_flags = unsafe { libc::fcntl(source.as_raw_fd(), libc::F_GETFL) };
        // SAFETY: copy owns its independently duplicated descriptor.
        let copy_flags = unsafe { libc::fcntl(copy.as_raw_fd(), libc::F_GETFL) };
        assert_eq!(source_flags, copy_flags);
        assert_eq!(bytes, length);
        // SAFETY: pointer and length are the exact mapping returned above.
        assert_eq!(
            unsafe { libc::munmap(pointer as *mut libc::c_void, length as usize) },
            0
        );
        drop(copy);
        // SAFETY: closing the duplicate must leave the original open.
        assert!(unsafe { libc::fcntl(source.as_raw_fd(), libc::F_GETFL) } >= 0);
    }
}
