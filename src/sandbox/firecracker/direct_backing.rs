//! Opt-in native backing handoff. This never manufactures a UB FD from SDK internals.
//! Cacheable RAM backings require file-private CoW; NC pmem uses an explicit
//! device-FD backend with isolated content verification.
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub const FIRST_BACKING_FD: i32 = 10;
pub const LEASE_FD_OFFSET: i32 = 32;
pub const MAX_PMEM_LAYERS: usize = 8;
pub const PMEM_ALIGNMENT: u64 = 2 * 1024 * 1024;
pub const FIRST_SEGMENT_FD: i32 = 64;
pub const MAX_SEGMENTS: usize = 32;
pub const FIRST_SOURCE_FD: i32 = 512;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BackingSpec {
    pub object_id: String,
    pub generation: String,
    pub sha256: String,
    pub bytes: u64,
    /// A trusted node-local provider. Object identity is portable; the socket is not.
    pub socket: PathBuf,
}

impl BackingSpec {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.socket
                .to_str()
                .is_some_and(|s| s.starts_with('/') && !s.contains('\0') && s.len() < 108),
            "native backing requires an absolute local provider socket shorter than 108 bytes"
        );
        ensure!(
            !self.object_id.is_empty()
                && self.object_id.len() <= 128
                && self
                    .object_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
            "invalid native backing object identity"
        );
        ensure!(
            !self.generation.is_empty()
                && self.generation.len() <= 128
                && self
                    .generation
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
            "invalid native backing generation"
        );
        let digest = self.sha256.strip_prefix("sha256:").unwrap_or("");
        ensure!(
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "native backing needs a lowercase sha256 content identity"
        );
        ensure!(
            self.bytes > 0 && self.bytes.is_multiple_of(4096),
            "native backing length must be a positive 4KiB multiple"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LayerIdentity {
    pub digest: String,
    pub size: u64,
}

/// Canonical memory image identity, independent of paths and UB replica incarnations.
pub fn memory_identity(config: &[u8], virtual_bytes: u64) -> Result<String> {
    #[derive(Deserialize)]
    struct Image {
        lowers: Vec<LayerIdentity>,
        upper: Option<serde_json::Value>,
    }
    let image: Image = serde_json::from_slice(config).context("parse memory image identities")?;
    if let Some(upper) = &image.upper {
        for key in ["data", "index", "target", "gzipIndex"] {
            ensure!(
                upper
                    .get(key)
                    .and_then(|value| value.as_str())
                    .unwrap_or("")
                    .is_empty(),
                "native backing identity cannot omit a mutable image upper"
            );
        }
    }
    ensure!(
        !image.lowers.is_empty(),
        "native RAM needs committed lower identities"
    );
    for layer in &image.lowers {
        ensure!(
            layer.size > 0
                && layer.digest.starts_with("sha256:")
                && layer.digest.len() == 71
                && layer.digest[7..]
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "memory lower is missing a committed digest/length"
        );
    }
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&(virtual_bytes, image.lowers))?)
    ))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MemoryBinding {
    pub version: u32,
    pub memory_image: String,
    /// Full linear, uncompressed RAM bytes, not an OverlayBD stored layer.
    pub backing: BackingSpec,
}

impl MemoryBinding {
    pub fn validate(&self, image: &[u8], virtual_bytes: u64) -> Result<()> {
        ensure!(self.version == 1, "unsupported native RAM binding version");
        self.backing.validate()?;
        ensure!(
            self.backing.bytes == virtual_bytes,
            "native RAM size differs from snapshot layout"
        );
        ensure!(
            self.memory_image == memory_identity(image, virtual_bytes)?,
            "native RAM binding belongs to another memory image"
        );
        Ok(())
    }
}

/// Supported immutable pmem lower filesystems; each must prove actual Guest DAX.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RootfsFilesystem {
    #[default]
    Erofs,
    Ext4,
}

impl RootfsFilesystem {
    fn as_str(self) -> &'static str {
        match self {
            Self::Erofs => "erofs",
            Self::Ext4 => "ext4",
        }
    }
}

/// Versions 1/2 are cold-boot only. Version 3 snapshots portable content
/// references; operators must retain immutable bases and provide fresh local
/// bindings on every restore node. An absent base is a hard restore error.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RootfsBinding {
    pub version: u32,
    /// Canonical source lower identity (memory_identity with virtual_bytes=0).
    /// Prevents a global experimental layout from substituting another requested image.
    pub source_image: String,
    /// Bottom to top OverlayFS priority; all layers must support guest DAX.
    pub layers: Vec<BackingSpec>,
    pub max_pmem_bytes: u64,
    /// Immutable lower filesystem; omitted legacy bindings remain EROFS.
    #[serde(default)]
    pub lower_filesystem: RootfsFilesystem,
    /// Required only by version 2: explicitly pinned device-aware executables.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_runtime: Option<DeviceRuntime>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DeviceRuntime {
    pub verifier: PathBuf,
    pub verifier_sha256: String,
    pub firecracker_sha256: String,
    pub verification_timeout_secs: u64,
}

impl DeviceRuntime {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.verifier
                .to_str()
                .is_some_and(|s| s.starts_with('/') && !s.contains('\0')),
            "device verifier requires an absolute Linux path"
        );
        for hash in [&self.verifier_sha256, &self.firecracker_sha256] {
            let value = hash.strip_prefix("sha256:").unwrap_or("");
            ensure!(
                value.len() == 64
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "device runtime requires explicit SHA256 binary pins"
            );
        }
        ensure!(
            (1..=600).contains(&self.verification_timeout_secs),
            "device verification timeout must be 1..600 seconds"
        );
        Ok(())
    }
}

pub fn verify_binary(path: &Path, expected: &str) -> Result<()> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).context("open pinned native runtime binary")?;
    ensure!(
        file.metadata()?.is_file(),
        "native runtime binary must be a regular file"
    );
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    ensure!(
        format!("sha256:{:x}", hash.finalize()) == expected,
        "pinned native runtime binary differs: {}",
        path.display()
    );
    Ok(())
}

impl RootfsBinding {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (self.version == 1 || self.version == 2 || self.version == 3)
                && !self.layers.is_empty()
                && self.layers.len() <= MAX_PMEM_LAYERS,
            "native rootfs requires 1..8 version-1/2/3 layers"
        );
        match (self.version, &self.device_runtime) {
            (1, None) => (),
            (2 | 3, Some(runtime)) => runtime.validate()?,
            _ => anyhow::bail!(
                "version-2/3 rootfs requires pinned device runtime; version-1 must omit it"
            ),
        }
        let mut total = 0u64;
        let mut identities = std::collections::HashSet::new();
        for layer in &self.layers {
            layer.validate()?;
            ensure!(
                layer.bytes.is_multiple_of(PMEM_ALIGNMENT),
                "pmem backing must be 2MiB aligned"
            );
            ensure!(
                identities.insert((&layer.object_id, &layer.generation)),
                "duplicate pmem layer"
            );
            total = total
                .checked_add(layer.bytes)
                .context("pmem capacity overflow")?;
        }
        ensure!(
            self.max_pmem_bytes > 0 && total <= self.max_pmem_bytes,
            "pmem capacity exceeds explicit per-Guest address-range budget"
        );
        Ok(())
    }

    pub fn boot_arg(&self) -> Result<String> {
        self.validate()?;
        Ok(format!(
            "aenv_pmem_rootfs={} aenv_pmem_fstype={}",
            self.layers.len(),
            self.lower_filesystem.as_str()
        ))
    }

    pub fn snapshot_identity(&self) -> Result<crate::sandbox::manifest::NativeRootfsSnapshot> {
        use crate::sandbox::manifest::{NativeRootfsLayer, NativeRootfsSnapshot};
        self.validate()?;
        ensure!(
            self.version == 3,
            "pmem capture/fork requires version-3 content rebinding support"
        );
        let mut unique = std::collections::HashSet::new();
        ensure!(
            self.layers
                .iter()
                .all(|l| unique.insert((&l.sha256, l.bytes))),
            "duplicate snapshot pmem content"
        );
        Ok(NativeRootfsSnapshot {
            version: 1,
            source_image: self.source_image.clone(),
            filesystem: self.lower_filesystem.as_str().to_string(),
            layers: self
                .layers
                .iter()
                .map(|l| NativeRootfsLayer {
                    sha256: l.sha256.clone(),
                    bytes: l.bytes,
                })
                .collect(),
        })
    }

    pub fn restore_binding(
        expected: &crate::sandbox::manifest::NativeRootfsSnapshot,
    ) -> Result<Self> {
        let path = std::env::var_os("AENV_DIRECT_ROOTFS_BINDING")
            .context("snapshot requires explicit node-local pmem content bindings")?;
        let binding: Self = read_binding(Path::new(&path))?;
        binding.validate_restore_identity(expected)?;
        Ok(binding)
    }

    pub fn validate_restore_identity(
        &self,
        expected: &crate::sandbox::manifest::NativeRootfsSnapshot,
    ) -> Result<()> {
        ensure!(
            self.snapshot_identity()? == *expected,
            "restore pmem content, order, length or filesystem differs from captured snapshot"
        );
        Ok(())
    }
}

pub fn read_binding<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 1024 * 1024,
        "native backing configuration exceeds 1MiB"
    );
    serde_json::from_slice(&bytes).context("parse native backing configuration")
}

#[cfg(target_os = "linux")]
pub use linux::PinnedBacking;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::fs::FileExt;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    /// The connection is a lease: provider must pin the object until it closes.
    /// The FD is kept CLOEXEC in aenv and duped only into the selected FC child.
    pub struct PinnedBacking {
        pub file: File,
        pub child_fd: RawFd,
        lease_file: File,
        _lease: UnixStream,
        nc_pmem_bytes: Option<u64>,
        extra_files: Vec<File>,
        segment_lengths: Vec<u64>,
    }

    impl PinnedBacking {
        pub fn acquire(spec: &BackingSpec, child_fd: RawFd, private_cow: bool) -> Result<Self> {
            Self::acquire_mode(spec, child_fd, private_cow, false)
        }

        /// Only the isolated verifier may read this mapping before FC startup.
        pub fn acquire_nc_pmem(spec: &BackingSpec, child_fd: RawFd) -> Result<Self> {
            ensure!(
                (FIRST_BACKING_FD..FIRST_BACKING_FD + MAX_PMEM_LAYERS as i32).contains(&child_fd)
                    && spec.bytes.is_multiple_of(PMEM_ALIGNMENT),
                "invalid NC pmem slot/length"
            );
            Self::acquire_mode(spec, child_fd, false, true)
        }

        fn acquire_mode(
            spec: &BackingSpec,
            child_fd: RawFd,
            private_cow: bool,
            nc_pmem: bool,
        ) -> Result<Self> {
            spec.validate()?;
            ensure!(
                (FIRST_BACKING_FD..FIRST_BACKING_FD + 16).contains(&child_fd),
                "invalid child backing slot"
            );
            let mut stream =
                UnixStream::connect(&spec.socket).context("connect native FD provider")?;
            stream.set_read_timeout(Some(Duration::from_secs(10)))?;
            stream.set_write_timeout(Some(Duration::from_secs(10)))?;
            let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of_val(&cred) as libc::socklen_t;
            // SAFETY: valid socket, writable ucred and its length.
            ensure!(
                unsafe {
                    libc::getsockopt(
                        stream.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_PEERCRED,
                        (&mut cred as *mut libc::ucred).cast(),
                        &mut len,
                    )
                } == 0,
                "cannot verify native provider credentials"
            );
            ensure!(
                cred.uid == unsafe { libc::geteuid() },
                "native provider must run as the runtime UID"
            );
            let protocol_version = if nc_pmem { 2 } else { 1 };
            let request = serde_json::json!({"version": protocol_version, "operation": "acquire", "objectId": spec.object_id,
                "generation": spec.generation, "sha256": spec.sha256, "bytes": spec.bytes,
                "privateCow": private_cow});
            let bytes = serde_json::to_vec(&request)?;
            stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
            stream.write_all(&bytes)?;
            let mut prefix = [0u8; 4];
            stream.read_exact(&mut prefix)?;
            let count = u32::from_be_bytes(prefix) as usize;
            ensure!(count <= 4096, "native provider response exceeds limit");
            let mut response = vec![0; count];
            stream.read_exact(&mut response)?;
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields, rename_all = "camelCase")]
            struct Response {
                version: u32,
                state: String,
                backing: BackingSpec,
                private_cow: bool,
                source: String,
                cache_mode: String,
                #[serde(default)]
                segment_lengths: Vec<u64>,
            }
            let response: Response = serde_json::from_slice(&response)?;
            ensure!(
                response.version == protocol_version
                    && response.state == "ready"
                    && response.backing == *spec,
                "native FD provider returned another object/generation/layout"
            );
            ensure!(
                !private_cow || response.private_cow,
                "provider does not support RAM private CoW"
            );
            ensure!(response.source == "ub", "unknown native backing source");
            if nc_pmem {
                ensure!(
                    response.source == "ub" && response.cache_mode == "nc" && !response.private_cow,
                    "NC pmem requires a UB device provider without a RAM CoW claim"
                );
            } else {
                ensure!(response.source == "ub" && response.cache_mode == "cc",
                    "FC path reopen requires cacheable backing; NC FD flags are not preserved by reopen");
            }
            let lengths = response.segment_lengths;
            if nc_pmem {
                ensure!(
                    !lengths.is_empty() && lengths.len() <= MAX_SEGMENTS,
                    "NC pmem requires a bounded complete device segment list"
                );
                let mut total = 0u64;
                for length in &lengths {
                    ensure!(
                        *length > 0 && length.is_multiple_of(PMEM_ALIGNMENT),
                        "invalid NC segment length"
                    );
                    total = total
                        .checked_add(*length)
                        .context("NC segment length overflow")?;
                }
                ensure!(
                    total == spec.bytes,
                    "NC segments do not cover the complete image"
                );
            } else {
                ensure!(
                    lengths.is_empty(),
                    "file-private RAM consumer does not accept segmented NC devices"
                );
            }
            let mut received = receive_fds(&stream, if nc_pmem { lengths.len() } else { 1 })?;
            for descriptor in &received {
                let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFL) };
                ensure!(
                    flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDONLY,
                    "provider must pass readonly descriptors"
                );
                if nc_pmem {
                    use std::os::unix::fs::FileTypeExt;
                    ensure!(
                        flags & libc::O_SYNC == libc::O_SYNC
                            && File::from(descriptor.try_clone()?)
                                .metadata()?
                                .file_type()
                                .is_char_device(),
                        "NC pmem requires readonly O_SYNC character device segments"
                    );
                } else {
                    ensure!(
                        flags & libc::O_SYNC == 0,
                        "NC/O_SYNC backing requires the explicit device backend"
                    );
                }
            }
            let mut file = File::from(received.remove(0));
            if !nc_pmem {
                ensure!(
                    file.seek(SeekFrom::End(0))? == spec.bytes,
                    "native FD capacity differs from declared full image"
                );
                // Whole-object verification is preparation work, not a cold/lazy read.
                // A provider must keep the object immutable after this check.
                let mut digest = Sha256::new();
                let mut buffer = vec![0u8; 1024 * 1024];
                let mut remaining = spec.bytes;
                while remaining != 0 {
                    let count = remaining.min(buffer.len() as u64) as usize;
                    // SCM_RIGHTS duplicates share a file description and cursor.
                    // Position-independent reads keep concurrent acquisitions isolated.
                    file.read_exact_at(&mut buffer[..count], spec.bytes - remaining)?;
                    digest.update(&buffer[..count]);
                    remaining -= count as u64;
                }
                ensure!(
                    format!("sha256:{:x}", digest.finalize()) == spec.sha256,
                    "native FD content does not match its published identity"
                );
            }
            // Use high sources so child dup2 actions cannot overwrite another source.
            let raw =
                unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, FIRST_SOURCE_FD) };
            ensure!(
                raw >= 0,
                "cannot pin native backing FD: {}",
                std::io::Error::last_os_error()
            );
            let file = unsafe { File::from_raw_fd(raw) };
            let mut extra_files = Vec::new();
            for descriptor in received {
                let raw = unsafe {
                    libc::fcntl(
                        descriptor.as_raw_fd(),
                        libc::F_DUPFD_CLOEXEC,
                        FIRST_SOURCE_FD,
                    )
                };
                ensure!(raw >= 0, "cannot pin NC device segment");
                extra_files.push(unsafe { File::from_raw_fd(raw) });
            }
            // Passing the lease into FC/verifier keeps the provider pinned even
            // if the Runtime exits before the child or a killed child is stuck.
            let lease_raw =
                unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_DUPFD_CLOEXEC, FIRST_SOURCE_FD) };
            ensure!(lease_raw >= 0, "cannot pin native backing lease FD");
            let lease_file = unsafe { File::from_raw_fd(lease_raw) };
            tracing::info!(object = %spec.object_id, generation = %spec.generation,
                source = %response.source, bytes = spec.bytes, child_fd, private_cow,
                "acquired native backing lease; physical sharing still requires target verification");
            Ok(Self {
                file,
                child_fd,
                lease_file,
                _lease: stream,
                nc_pmem_bytes: nc_pmem.then_some(spec.bytes),
                extra_files,
                segment_lengths: lengths,
            })
        }

        pub fn child_path(&self) -> PathBuf {
            match self.nc_pmem_bytes {
                Some(_) => self.segmented_path(self.segment_child_start()),
                None => PathBuf::from(format!("/proc/self/fd/{}", self.child_fd)),
            }
        }

        fn segment_child_start(&self) -> RawFd {
            FIRST_SEGMENT_FD + (self.child_fd - FIRST_BACKING_FD) * MAX_SEGMENTS as i32
        }

        fn segmented_path(&self, first: RawFd) -> PathBuf {
            let segments = self
                .segment_lengths
                .iter()
                .enumerate()
                .map(|(index, bytes)| format!("{}@{bytes}", first + index as i32))
                .collect::<Vec<_>>()
                .join(",");
            PathBuf::from(format!(
                "aenv-pmem-fd:v2:{}:nc:{segments}",
                self.nc_pmem_bytes.expect("NC backing")
            ))
        }

        fn data_handoffs(&self, first: RawFd) -> Vec<(RawFd, RawFd)> {
            std::iter::once(&self.file)
                .chain(self.extra_files.iter())
                .enumerate()
                .map(|(index, file)| (file.as_raw_fd(), first + index as i32))
                .collect()
        }

        pub fn handoffs(&self) -> Vec<(RawFd, RawFd)> {
            let first = if self.nc_pmem_bytes.is_some() {
                self.segment_child_start()
            } else {
                self.child_fd
            };
            let mut values = self.data_handoffs(first);
            values.push((self.lease_file.as_raw_fd(), self.child_fd + LEASE_FD_OFFSET));
            values
        }

        pub fn verification_path(&self) -> PathBuf {
            self.segmented_path(FIRST_SEGMENT_FD)
        }

        pub fn verification_handoffs(&self) -> Vec<(RawFd, RawFd)> {
            let mut values = self.data_handoffs(FIRST_SEGMENT_FD);
            values.push((
                self.lease_file.as_raw_fd(),
                FIRST_BACKING_FD + LEASE_FD_OFFSET,
            ));
            values
        }
    }

    fn receive_fds(stream: &UnixStream, expected: usize) -> Result<Vec<OwnedFd>> {
        ensure!(
            (1..=MAX_SEGMENTS).contains(&expected),
            "invalid segment descriptor count"
        );
        let mut byte = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: 1,
        };
        // usize storage provides cmsghdr alignment. Capacity allows detecting extras.
        let mut control = [0usize; 128];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = std::mem::size_of_val(&control);
        let rc = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
        ensure!(
            rc >= 0,
            "receive native FD: {}",
            std::io::Error::last_os_error()
        );
        let mut fds = Vec::new();
        // SAFETY: kernel populated msg/control; received descriptors are immediately owned.
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                    let bytes = (*cmsg).cmsg_len.saturating_sub(libc::CMSG_LEN(0) as usize);
                    for i in 0..bytes / std::mem::size_of::<RawFd>() {
                        fds.push(OwnedFd::from_raw_fd(
                            *libc::CMSG_DATA(cmsg).cast::<RawFd>().add(i),
                        ));
                    }
                }
                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }
        }
        ensure!(
            rc == 1
                && byte[0] == b'F'
                && msg.msg_flags & libc::MSG_CTRUNC == 0
                && fds.len() == expected,
            "native provider must pass exactly the complete non-truncated FD set"
        );
        Ok(fds)
    }

    #[cfg(test)]
    fn receive_fd(stream: &UnixStream) -> Result<OwnedFd> {
        Ok(receive_fds(stream, 1)?
            .pop()
            .expect("one checked descriptor"))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        fn send_fds(stream: &UnixStream, fds: &[RawFd]) {
            let mut byte = b'F';
            let mut iov = libc::iovec {
                iov_base: (&mut byte as *mut u8).cast(),
                iov_len: 1,
            };
            let mut control = [0usize; 32];
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen =
                unsafe { libc::CMSG_SPACE(std::mem::size_of_val(fds) as u32) as usize };
            unsafe {
                let header = libc::CMSG_FIRSTHDR(&msg);
                (*header).cmsg_level = libc::SOL_SOCKET;
                (*header).cmsg_type = libc::SCM_RIGHTS;
                (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(fds) as u32) as usize;
                std::ptr::copy_nonoverlapping(
                    fds.as_ptr().cast::<u8>(),
                    libc::CMSG_DATA(header),
                    std::mem::size_of_val(fds),
                );
                assert_eq!(libc::sendmsg(stream.as_raw_fd(), &msg, 0), 1);
            }
        }

        #[test]
        fn scm_rights_receive_owns_one_cloexec_descriptor() {
            let (a, b) = UnixStream::pair().unwrap();
            let original = File::open("/dev/null").unwrap();
            send_fds(&a, &[original.as_raw_fd()]);
            let received = receive_fd(&b).unwrap();
            assert_ne!(received.as_raw_fd(), original.as_raw_fd());
            assert_ne!(
                unsafe { libc::fcntl(received.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
        }

        #[test]
        fn scm_rights_rejects_extra_descriptors() {
            let (a, b) = UnixStream::pair().unwrap();
            let original = File::open("/dev/null").unwrap();
            send_fds(&a, &[original.as_raw_fd(), original.as_raw_fd()]);
            assert!(receive_fd(&b).is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn device_version_requires_explicit_binary_pins_and_cannot_downgrade() {
        let mut root = RootfsBinding {
            version: 2,
            source_image: "test".into(),
            layers: vec![spec()],
            max_pmem_bytes: PMEM_ALIGNMENT,
            lower_filesystem: RootfsFilesystem::Erofs,
            device_runtime: None,
        };
        assert!(root.validate().is_err());
        root.device_runtime = Some(DeviceRuntime {
            verifier: "/opt/aenv-native-fd-verify".into(),
            verifier_sha256: format!("sha256:{}", "a".repeat(64)),
            firecracker_sha256: format!("sha256:{}", "b".repeat(64)),
            verification_timeout_secs: 60,
        });
        assert!(root.validate().is_ok());
        root.version = 1;
        assert!(root.validate().is_err());
        root.version = 2;
        root.device_runtime
            .as_mut()
            .unwrap()
            .verification_timeout_secs = 0;
        assert!(root.validate().is_err());
    }
    fn spec() -> BackingSpec {
        BackingSpec {
            object_id: "base".into(),
            generation: "v1".into(),
            sha256: format!("sha256:{}", "a".repeat(64)),
            bytes: PMEM_ALIGNMENT,
            socket: "/run/user/1000/backing.sock".into(),
        }
    }
    #[test]
    fn snapshot_content_identity_rebinds_nodes_but_rejects_changed_base() {
        let mut binding = RootfsBinding {
            version: 3,
            source_image: "source".into(),
            layers: vec![spec()],
            max_pmem_bytes: PMEM_ALIGNMENT * 4,
            lower_filesystem: RootfsFilesystem::Ext4,
            device_runtime: Some(DeviceRuntime {
                verifier: "/opt/verifier".into(),
                verifier_sha256: format!("sha256:{}", "b".repeat(64)),
                firecracker_sha256: format!("sha256:{}", "c".repeat(64)),
                verification_timeout_secs: 60,
            }),
        };
        let identity = binding.snapshot_identity().unwrap();
        let encoded = serde_json::to_string(&identity).unwrap();
        assert!(
            !encoded.contains("socket")
                && !encoded.contains("generation")
                && !encoded.contains("verifier")
        );
        binding.layers[0].socket = "/run/another-node/provider.sock".into();
        binding.layers[0].object_id = "republished".into();
        binding.layers[0].generation = "new-generation".into();
        binding.validate_restore_identity(&identity).unwrap();
        binding.layers[0].sha256 = format!("sha256:{}", "d".repeat(64));
        assert!(binding.validate_restore_identity(&identity).is_err());
        binding.layers[0] = spec();
        binding.layers[0].bytes *= 2;
        assert!(binding.validate_restore_identity(&identity).is_err());
        binding.layers[0] = spec();
        binding.version = 2;
        assert!(binding.snapshot_identity().is_err());
    }
    #[test]
    fn memory_identity_ignores_paths_but_binds_order_and_size() {
        let a = format!(
            r#"{{"lowers":[{{"digest":"sha256:{}","size":32,"file":"/a"}}]}}"#,
            "a".repeat(64)
        );
        let b = a.replace("/a", "/node-b");
        assert_eq!(
            memory_identity(a.as_bytes(), 4096).unwrap(),
            memory_identity(b.as_bytes(), 4096).unwrap()
        );
        assert_ne!(
            memory_identity(a.as_bytes(), 4096).unwrap(),
            memory_identity(a.as_bytes(), 8192).unwrap()
        );
        assert!(memory_identity(br#"{"lowers":[{"digest":"","size":32}]}"#, 4096).is_err());
        let mutable = a.replace(
            "\"lowers\":",
            "\"upper\":{\"data\":\"private.data\"},\"lowers\":",
        );
        assert!(memory_identity(mutable.as_bytes(), 4096).is_err());
    }
    #[test]
    fn rejects_unbound_or_compressed_ram_size() {
        let image = format!(
            r#"{{"lowers":[{{"digest":"sha256:{}","size":32}}]}}"#,
            "a".repeat(64)
        );
        let binding = MemoryBinding {
            version: 1,
            memory_image: memory_identity(image.as_bytes(), 4096).unwrap(),
            backing: spec(),
        };
        assert!(binding.validate(image.as_bytes(), 4096).is_err());
        assert!(binding.validate(image.as_bytes(), PMEM_ALIGNMENT).is_err());
    }
    #[test]
    fn rootfs_has_explicit_capacity_and_unique_layers() {
        let mut root = RootfsBinding {
            version: 1,
            source_image: "test".into(),
            layers: vec![spec()],
            max_pmem_bytes: PMEM_ALIGNMENT,
            lower_filesystem: RootfsFilesystem::Erofs,
            device_runtime: None,
        };
        assert_eq!(
            root.boot_arg().unwrap(),
            "aenv_pmem_rootfs=1 aenv_pmem_fstype=erofs"
        );
        root.lower_filesystem = RootfsFilesystem::Ext4;
        assert_eq!(
            root.boot_arg().unwrap(),
            "aenv_pmem_rootfs=1 aenv_pmem_fstype=ext4"
        );
        root.max_pmem_bytes -= 1;
        assert!(root.validate().is_err());
        root.max_pmem_bytes = 2 * PMEM_ALIGNMENT;
        root.layers.push(spec());
        assert!(root.validate().is_err());
    }
    #[test]
    fn valid_ram_binding_matches_full_image_and_order() {
        let image = format!(
            r#"{{"lowers":[{{"digest":"sha256:{}","size":32}},{{"digest":"sha256:{}","size":64}}]}}"#,
            "a".repeat(64),
            "b".repeat(64)
        );
        let binding = MemoryBinding {
            version: 1,
            memory_image: memory_identity(image.as_bytes(), PMEM_ALIGNMENT).unwrap(),
            backing: spec(),
        };
        assert!(binding.validate(image.as_bytes(), PMEM_ALIGNMENT).is_ok());
        let reversed = format!(
            r#"{{"lowers":[{{"digest":"sha256:{}","size":64}},{{"digest":"sha256:{}","size":32}}]}}"#,
            "b".repeat(64),
            "a".repeat(64)
        );
        assert!(binding
            .validate(reversed.as_bytes(), PMEM_ALIGNMENT)
            .is_err());
    }
    #[test]
    fn rejects_paths_bad_hashes_and_unaligned_pmem() {
        let mut value = spec();
        value.object_id = "../bad".into();
        assert!(value.validate().is_err());
        value = spec();
        value.sha256 = "sha256:BAD".into();
        assert!(value.validate().is_err());
        value = spec();
        value.bytes = 4096;
        assert!(RootfsBinding {
            version: 1,
            source_image: "test".into(),
            layers: vec![value],
            max_pmem_bytes: PMEM_ALIGNMENT,
            lower_filesystem: RootfsFilesystem::Erofs,
            device_runtime: None
        }
        .validate()
        .is_err());
    }

    #[test]
    fn rootfs_filesystem_defaults_to_erofs_and_refuses_unknown_types() {
        let legacy = serde_json::json!({
            "version": 1, "sourceImage": "test", "layers": [spec()],
            "maxPmemBytes": PMEM_ALIGNMENT
        });
        let binding: RootfsBinding = serde_json::from_value(legacy.clone()).unwrap();
        assert_eq!(binding.lower_filesystem, RootfsFilesystem::Erofs);
        let mut ext4 = legacy.clone();
        ext4["lowerFilesystem"] = serde_json::json!("ext4");
        let binding: RootfsBinding = serde_json::from_value(ext4).unwrap();
        assert!(binding
            .boot_arg()
            .unwrap()
            .ends_with("aenv_pmem_fstype=ext4"));
        for value in [serde_json::json!("xfs"), serde_json::json!(true)] {
            let mut unknown = legacy.clone();
            unknown["lowerFilesystem"] = value;
            assert!(serde_json::from_value::<RootfsBinding>(unknown).is_err());
        }
    }
}
