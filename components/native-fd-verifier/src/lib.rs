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
    let (_file, _, pointer, bytes) = backing.map(true)?;
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
