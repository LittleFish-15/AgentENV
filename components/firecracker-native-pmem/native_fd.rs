// SPDX-License-Identifier: Apache-2.0
//! Readonly inherited NC segments or an explicitly validated FS-DAX file.
//! Shared with the isolated verifier; the FC patch embeds the same source.
use std::io;

const PREFIX: &str = "aenv-pmem-fd:";
pub const ALIGNMENT: u64 = 2 * 1024 * 1024;
pub const FIRST_SEGMENT_FD: i32 = 64;
pub const MAX_SEGMENTS: usize = 32;
pub const MAX_LAYERS: i32 = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativePmemFd {
    segments: Vec<(i32, u64)>,
    bytes: u64,
    content_sha256: Option<String>,
    fs_dax: bool,
}

pub fn is_native_pmem_path(path: &str) -> bool {
    path.starts_with(PREFIX)
}

fn decimal(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|b| b.is_ascii_digit())
        && (value.len() == 1 || !value.starts_with('0'))
}

fn number(value: &str) -> io::Result<u64> {
    if !decimal(value) {
        return Err(invalid(
            "native descriptor requires canonical decimal integers",
        ));
    }
    value
        .parse()
        .map_err(|_| invalid("native integer overflow"))
}

impl NativePmemFd {
    pub fn parse(path: &str) -> io::Result<Option<Self>> {
        let Some(value) = path.strip_prefix(PREFIX) else {
            return Ok(None);
        };
        if value.len() > 4096 {
            return Err(invalid(
                "native descriptor exceeds bounded segment metadata",
            ));
        }
        if let Some(value) = value.strip_prefix("v4:") {
            let parts: Vec<_> = value.split(':').collect();
            if parts.len() != 4
                || parts[2] != "fsdax"
                || parts[0].len() != 64
                || !parts[0]
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(invalid("invalid FS-DAX content descriptor"));
            }
            let bytes = number(parts[1])?;
            let fd = i32::try_from(number(parts[3])?).map_err(|_| invalid("FD overflow"))?;
            if bytes == 0
                || bytes % 4096 != 0
                || bytes > isize::MAX as u64 - ALIGNMENT
                || !((10..26).contains(&fd) || (64..320).contains(&fd))
            {
                return Err(invalid("invalid FS-DAX length or inherited FD"));
            }
            return Ok(Some(Self {
                segments: vec![(fd, bytes)],
                bytes,
                content_sha256: Some(parts[0].to_owned()),
                fs_dax: true,
            }));
        }
        if let Some(value) = value.strip_prefix("v3:") {
            let (digest, rest) = value
                .split_once(':')
                .ok_or_else(|| invalid("missing v3 content identity"))?;
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(invalid("invalid v3 content SHA256"));
            }
            let mut parsed = Self::parse(&format!("{PREFIX}v2:{rest}"))?
                .ok_or_else(|| invalid("missing v3 segment descriptor"))?;
            parsed.content_sha256 = Some(digest.to_owned());
            return Ok(Some(parsed));
        }
        let parts: Vec<_> = value.split(':').collect();
        if parts.len() != 4 {
            return Err(invalid("invalid native pmem descriptor"));
        }
        let (bytes, segments) = match parts[0] {
            "v1" if parts[3] == "nc" => {
                let fd = i32::try_from(number(parts[1])?).map_err(|_| invalid("FD overflow"))?;
                let bytes = number(parts[2])?;
                if !(10..=17).contains(&fd) {
                    return Err(invalid("legacy native pmem needs FD 10..17"));
                }
                (bytes, vec![(fd, bytes)])
            }
            "v2" if parts[2] == "nc" => {
                let bytes = number(parts[1])?;
                let mut segments = Vec::new();
                for item in parts[3].split(',') {
                    if segments.len() == MAX_SEGMENTS {
                        return Err(invalid("too many native segments"));
                    }
                    let (fd, length) = item
                        .split_once('@')
                        .ok_or_else(|| invalid("expected FD@BYTES"))?;
                    let fd = i32::try_from(number(fd)?).map_err(|_| invalid("FD overflow"))?;
                    segments.push((fd, number(length)?));
                }
                let first = segments
                    .first()
                    .ok_or_else(|| invalid("missing native segments"))?
                    .0;
                if !(FIRST_SEGMENT_FD..FIRST_SEGMENT_FD + MAX_LAYERS * MAX_SEGMENTS as i32)
                    .contains(&first)
                    || (first - FIRST_SEGMENT_FD) % MAX_SEGMENTS as i32 != 0
                    || segments
                        .iter()
                        .enumerate()
                        .any(|(index, (fd, _))| *fd != first + index as i32)
                {
                    return Err(invalid(
                        "native segments need one ordered reserved FD group",
                    ));
                }
                (bytes, segments)
            }
            _ => return Err(invalid("unsupported native pmem version or cache mode")),
        };
        let mut total = 0u64;
        for (_, length) in &segments {
            if *length == 0 || !length.is_multiple_of(ALIGNMENT) {
                return Err(invalid(
                    "native segment length must be a positive 2MiB multiple",
                ));
            }
            total = total
                .checked_add(*length)
                .ok_or_else(|| invalid("native length overflow"))?;
        }
        if bytes != total || bytes == 0 || bytes > isize::MAX as u64 - ALIGNMENT {
            return Err(invalid(
                "native segments do not cover the declared image exactly",
            ));
        }
        Ok(Some(Self {
            segments,
            bytes,
            content_sha256: None,
            fs_dax: false,
        }))
    }

    /// Content reference only; process-local descriptors never enter snapshots.
    pub fn snapshot_reference(&self) -> Option<String> {
        self.content_sha256
            .as_ref()
            .map(|sha| format!("aenv-pmem-content:v1:{sha}:{}", self.bytes))
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    pub fn is_fs_dax(&self) -> bool {
        self.fs_dax
    }

    #[cfg(target_os = "linux")]
    pub fn map(self, read_only: bool) -> io::Result<(std::fs::File, u64, u64, u64)> {
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::fs::FileTypeExt;
        if !read_only {
            return Err(invalid("native device pmem is read-only"));
        }
        let mut files = Vec::new();
        for (fd, length) in &self.segments {
            // SAFETY: fcntl validates fd and returns a newly owned descriptor.
            let raw = unsafe { libc::fcntl(*fd, libc::F_DUPFD_CLOEXEC, 512) };
            if raw < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: raw was just allocated above.
            let file = unsafe { std::fs::File::from_raw_fd(raw) };
            // SAFETY: file remains open throughout validation and mapping.
            let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            if self.fs_dax {
                validate_fs_dax_file(&file, *length)?;
            } else if flags & libc::O_ACCMODE != libc::O_RDONLY
                || flags & libc::O_SYNC != libc::O_SYNC
                || !file.metadata()?.file_type().is_char_device()
            {
                return Err(invalid(
                    "native segments must be readonly O_SYNC character devices",
                ));
            }
            files.push(file);
        }
        let length = self.bytes as usize;
        let alignment = ALIGNMENT as usize;
        let reserve_length = length + alignment;
        // SAFETY: reserve inaccessible address space only, not physical UB memory.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                reserve_length,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        struct Reservation {
            address: *mut libc::c_void,
            length: usize,
        }
        impl Drop for Reservation {
            fn drop(&mut self) {
                if self.length != 0 {
                    // SAFETY: only the still-owned reservation is unmapped.
                    unsafe {
                        libc::munmap(self.address, self.length);
                    }
                }
            }
        }
        let mut owned = Reservation {
            address: base,
            length: reserve_length,
        };
        let address = (base as usize + alignment - 1) & !(alignment - 1);
        let mut offset = 0usize;
        for (file, (_, bytes)) in files.iter().zip(&self.segments) {
            let count = *bytes as usize;
            // SAFETY: MAP_FIXED replaces only this process's own inaccessible
            // reservation; all ranges are disjoint and their sum was validated.
            let mapped = unsafe {
                libc::mmap(
                    (address + offset) as *mut libc::c_void,
                    count,
                    libc::PROT_READ,
                    libc::MAP_SHARED | libc::MAP_FIXED,
                    file.as_raw_fd(),
                    0,
                )
            };
            if mapped == libc::MAP_FAILED {
                return Err(io::Error::last_os_error());
            }
            offset += count;
        }
        let head = address - base as usize;
        if head != 0 {
            // SAFETY: trim only our unused prefix. Update ownership immediately
            // so error cleanup cannot unmap an address another thread reuses.
            if unsafe { libc::munmap(base, head) } != 0 {
                return Err(io::Error::last_os_error());
            }
            owned.address = address as *mut libc::c_void;
            owned.length -= head;
        }
        let tail = owned.length - length;
        if tail != 0 {
            // SAFETY: trim only our unused suffix.
            if unsafe { libc::munmap((address + length) as *mut libc::c_void, tail) } != 0 {
                return Err(io::Error::last_os_error());
            }
            owned.length = length;
        }
        owned.length = 0; // Transfer the complete image mapping to Pmem/its verifier.
                          // Every segment VMA retains its file reference after these duplicates
                          // close. The inherited provider socket separately pins the UB generation.
        Ok((files.remove(0), self.bytes, address as u64, self.bytes))
    }
}

/// FS-DAX is a separate contract from an NC character FD or ordinary cached file.
/// This proves local file properties, not UB provenance or cross-node identity.
#[cfg(target_os = "linux")]
pub fn validate_fs_dax_file(file: &std::fs::File, bytes: u64) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    const ATTR_DAX: u64 = 0x0020_0000;
    // SAFETY: the borrowed descriptor remains open during this check.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 || flags & libc::O_ACCMODE != libc::O_RDONLY || flags & libc::O_SYNC != 0 {
        return Err(invalid(
            "FS-DAX backing requires an exact-length readonly regular file",
        ));
    }
    // SAFETY: zero is a valid initial value for this C output structure.
    let mut st: libc::statx = unsafe { std::mem::zeroed() };
    // SAFETY: valid output and NUL-terminated empty path. AT_EMPTY_PATH binds
    // the check to the inherited open file, not a pathname.
    if unsafe {
        libc::statx(
            file.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            libc::STATX_BASIC_STATS,
            &mut st,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if st.stx_mask & (libc::STATX_TYPE | libc::STATX_SIZE) != (libc::STATX_TYPE | libc::STATX_SIZE)
        || st.stx_mode as libc::mode_t & libc::S_IFMT != libc::S_IFREG
        || st.stx_attributes_mask & ATTR_DAX == 0
        || st.stx_attributes & ATTR_DAX == 0
        || st.stx_size != bytes
    {
        return Err(invalid("inherited file does not have active S_DAX"));
    }
    // SAFETY: zero is a valid initial value for this C output structure.
    let mut fs: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: valid open FD and writable statvfs output structure.
    if unsafe { libc::fstatvfs(file.as_raw_fd(), &mut fs) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if fs.f_flag as u64 & 1 == 0 {
        return Err(invalid("FS-DAX base must be on a readonly mount"));
    }
    Ok(())
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fs_dax_descriptors_bind_content_and_reject_raw_device_syntax() {
        let digest = "a".repeat(64);
        let descriptor = format!("aenv-pmem-fd:v4:{digest}:4096:fsdax:18");
        let parsed = NativePmemFd::parse(&descriptor).unwrap().unwrap();
        assert!(parsed.is_fs_dax());
        assert_eq!(
            parsed.snapshot_reference().unwrap(),
            format!("aenv-pmem-content:v1:{digest}:4096")
        );
        for (bytes, mode, fd) in [
            (0, "fsdax", 18),
            (4095, "fsdax", 18),
            (4096, "nc", 18),
            (4096, "fsdax", 3),
            (4096, "fsdax", 320),
        ] {
            assert!(
                NativePmemFd::parse(&format!("aenv-pmem-fd:v4:{digest}:{bytes}:{mode}:{fd}"))
                    .is_err()
            );
        }
        assert!(NativePmemFd::parse(&descriptor.replace(&digest, &"G".repeat(64))).is_err());
    }
    #[test]
    fn ordinary_files_keep_the_existing_backend() {
        assert!(NativePmemFd::parse("/tmp/base.erofs").unwrap().is_none());
    }
    #[test]
    fn supports_legacy_and_exact_segmented_lengths() {
        assert_eq!(
            NativePmemFd::parse("aenv-pmem-fd:v1:10:4194304:nc")
                .unwrap()
                .unwrap()
                .bytes(),
            4194304
        );
        let value = NativePmemFd::parse("aenv-pmem-fd:v2:6291456:nc:64@4194304,65@2097152")
            .unwrap()
            .unwrap();
        assert_eq!(value.segments, [(64, 4194304), (65, 2097152)]);
        assert_eq!(value.bytes(), 6291456);
    }
    #[test]
    fn rejects_ambiguous_duplicate_disordered_or_incomplete_segments() {
        for value in [
            "aenv-pmem-fd:v2:6291456:nc:64@4194304",
            "aenv-pmem-fd:v2:4194304:nc:64@2097152,64@2097152",
            "aenv-pmem-fd:v2:4194304:nc:65@2097152,66@2097152",
            "aenv-pmem-fd:v2:4194304:nc:64@2097152,66@2097152",
            "aenv-pmem-fd:v2:2097152:nc:320@2097152",
            "aenv-pmem-fd:v2:4096:nc:64@4096",
            "aenv-pmem-fd:v2:2097152:cc:64@2097152",
            "aenv-pmem-fd:v1:+10:4194304:nc",
            "aenv-pmem-fd:v1:010:4194304:nc",
            "aenv-pmem-fd:v1:18:4194304:nc",
            "aenv-pmem-fd:v2:18446744073709551615:nc:64@18446744073709551615",
        ] {
            assert!(NativePmemFd::parse(value).is_err(), "{value}");
        }
    }
    #[test]
    fn rejects_more_than_one_reserved_group() {
        let list = (64..97)
            .map(|fd| format!("{fd}@2097152"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(
            NativePmemFd::parse(&format!("aenv-pmem-fd:v2:{}:nc:{list}", 33 * ALIGNMENT)).is_err()
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn refuses_writable_mapping_before_accessing_any_fd() {
        let value = NativePmemFd::parse("aenv-pmem-fd:v2:2097152:nc:64@2097152")
            .unwrap()
            .unwrap();
        assert!(value.map(false).is_err());
    }
}
