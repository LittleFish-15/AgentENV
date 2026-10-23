//! Device reads are isolated in this helper process, never in the Runtime.
use std::io;

// The FC patch embeds the same parser/mapping source. No second mapping algorithm.
#[path = "../../firecracker-native-pmem/native_fd.rs"]
#[allow(dead_code)]
mod native_fd;

pub fn validate(descriptor: &str, expected: &str) -> io::Result<()> {
    if native_fd::NativePmemFd::parse(descriptor)?.is_none()
        || expected.len() != 64
        || !expected
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid verifier arguments",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn verify(descriptor: &str, expected: &str) -> io::Result<()> {
    verify_mode(descriptor, expected, false)
}

#[cfg(target_os = "linux")]
pub fn verify_mode(descriptor: &str, expected: &str, private_cow: bool) -> io::Result<()> {
    use sha2::{Digest, Sha256};
    validate(descriptor, expected)?;
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: an all-zero limit only affects this disposable child.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let status = std::fs::read_to_string("/proc/self/status")?;
    let caps: Vec<_> = status
        .lines()
        .filter(|line| {
            ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"]
                .iter()
                .any(|key| line.starts_with(key))
        })
        .collect();
    // SAFETY: geteuid has no pointer arguments or side effects.
    if unsafe { libc::geteuid() } == 0
        || caps.len() != 4
        || caps.iter().any(|line| {
            line.split_whitespace()
                .nth(1)
                .and_then(|s| u64::from_str_radix(s, 16).ok())
                != Some(0)
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "helper requires non-root and zero capabilities",
        ));
    }
    let backing = native_fd::NativePmemFd::parse(descriptor)?.expect("validated descriptor");
    if private_cow && !backing.is_fs_dax() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private mapping verification requires FS-DAX",
        ));
    }
    if let Some(reference) = backing.snapshot_reference() {
        if reference != format!("aenv-pmem-content:v1:{expected}:{}", backing.bytes()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "descriptor digest differs",
            ));
        }
    }
    let (file, _, pointer, bytes) = backing.map(true)?;
    struct Mapping(*mut libc::c_void, usize);
    impl Drop for Mapping {
        fn drop(&mut self) {
            // SAFETY: this guard owns the exact successfully mapped image.
            unsafe {
                libc::munmap(self.0, self.1);
            }
        }
    }
    let mapped = Mapping(pointer as *mut libc::c_void, bytes as usize);
    let mut hash = Sha256::new();
    let mut offset = 0;
    while offset < mapped.1 {
        let count = (mapped.1 - offset).min(1024 * 1024);
        // SAFETY: offset/count stay within the readonly image; faults terminate
        // only this helper. No signal recovery or local data-copy fallback.
        hash.update(unsafe {
            std::slice::from_raw_parts(mapped.0.cast::<u8>().add(offset), count)
        });
        offset += count;
    }
    if format!("{:x}", hash.finalize()) != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native content SHA256 mismatch",
        ));
    }
    if private_cow {
        use std::os::fd::AsRawFd;
        // Two private views exercise first-write isolation without modifying the
        // readonly base. This is a Host VM test, not Guest/KVM or UB attestation.
        let make_private = || -> io::Result<Mapping> {
            // SAFETY: validated file covers bytes; the guard owns the new range.
            let ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    bytes as usize,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE,
                    file.as_raw_fd(),
                    0,
                )
            };
            if ptr == libc::MAP_FAILED {
                return Err(io::Error::last_os_error());
            }
            Ok(Mapping(ptr, bytes as usize))
        };
        let first = make_private()?;
        let second = make_private()?;
        for offset in [0, bytes as usize - 1] {
            // SAFETY: all pointers are inside owned mappings. Volatile accesses
            // force actual faults and reads. No signal recovery or fallback.
            unsafe {
                let base = mapped.0.cast::<u8>().add(offset);
                let a = first.0.cast::<u8>().add(offset);
                let b = second.0.cast::<u8>().add(offset);
                let original = base.read_volatile();
                if a.read_volatile() != original || b.read_volatile() != original {
                    return Err(io::Error::other("private views differ before write"));
                }
                a.write_volatile(original ^ 0x5a);
                if a.read_volatile() != original ^ 0x5a
                    || b.read_volatile() != original
                    || base.read_volatile() != original
                {
                    return Err(io::Error::other("private write changed peer or base"));
                }
                b.write_volatile(original ^ 0xa5);
                if a.read_volatile() != original ^ 0x5a
                    || b.read_volatile() != original ^ 0xa5
                    || base.read_volatile() != original
                {
                    return Err(io::Error::other("second private write was not isolated"));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_the_whole_range_and_identity_before_any_device_access() {
        let descriptor = "aenv-pmem-fd:v2:6291456:nc:64@4194304,65@2097152";
        assert!(validate(descriptor, &"a".repeat(64)).is_ok());
        for path in ["/tmp/file", "aenv-pmem-fd:v2:6291456:nc:64@4194304"] {
            assert!(validate(path, &"a".repeat(64)).is_err());
        }
        for hash in [
            "a".repeat(63),
            "G".repeat(64),
            format!("sha256:{}", "a".repeat(64)),
        ] {
            assert!(validate(descriptor, &hash).is_err());
        }
    }
}
