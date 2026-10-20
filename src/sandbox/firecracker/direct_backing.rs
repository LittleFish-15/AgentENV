//! Opt-in native backing handoff. This never manufactures a UB FD from SDK internals.
//! A provider must export a readable, seekable, mmap-compatible immutable object.
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub const FIRST_BACKING_FD: i32 = 10;
pub const MAX_PMEM_LAYERS: usize = 8;
pub const PMEM_ALIGNMENT: u64 = 2 * 1024 * 1024;

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
        for key in ["data", "index", "target"] {
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

/// Experimental cold-boot layout. Capture is deliberately refused until the new
/// pmem device/backing identities can be committed and restored durably.
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
}

impl RootfsBinding {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && !self.layers.is_empty() && self.layers.len() <= MAX_PMEM_LAYERS,
            "native rootfs requires 1..8 version-1 layers"
        );
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
        Ok(format!("aenv_pmem_rootfs={}", self.layers.len()))
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
        _lease: UnixStream,
    }

    impl PinnedBacking {
        pub fn acquire(spec: &BackingSpec, child_fd: RawFd, private_cow: bool) -> Result<Self> {
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
            let request = serde_json::json!({"version": 1, "operation": "acquire", "objectId": spec.object_id,
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
                /// Local file fixtures must never be reported as UB hardware validation.
                source: String,
                cache_mode: String,
            }
            let response: Response = serde_json::from_slice(&response)?;
            ensure!(
                response.version == 1 && response.state == "ready" && response.backing == *spec,
                "native FD provider returned another object/generation/layout"
            );
            ensure!(
                !private_cow || response.private_cow,
                "provider does not support RAM private CoW"
            );
            ensure!(
                response.source == "ub" || response.source == "sealed_memfd_fixture",
                "unknown native backing source"
            );
            ensure!((response.source == "ub" && response.cache_mode == "cc")
                || (response.source == "sealed_memfd_fixture" && response.cache_mode == "local"),
                "FC path reopen requires cacheable backing; NC FD flags are not preserved by reopen");
            let received = receive_fd(&stream)?;
            let flags = unsafe { libc::fcntl(received.as_raw_fd(), libc::F_GETFL) };
            ensure!(
                flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDONLY,
                "provider must pass a read-only FD"
            );
            ensure!(
                flags & libc::O_SYNC == 0,
                "NC/O_SYNC native FDs require an explicit FC FD-aware backend, not path reopen"
            );
            if response.source == "sealed_memfd_fixture" {
                let seals = unsafe { libc::fcntl(received.as_raw_fd(), libc::F_GET_SEALS) };
                let required = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK;
                ensure!(
                    seals >= 0 && seals & required == required,
                    "fixture FD is not immutable"
                );
            }
            let mut file = File::from(received);
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
            // Use high sources so child dup2 actions cannot overwrite another source.
            let raw = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 256) };
            ensure!(
                raw >= 0,
                "cannot pin native backing FD: {}",
                std::io::Error::last_os_error()
            );
            let file = unsafe { File::from_raw_fd(raw) };
            tracing::info!(object = %spec.object_id, generation = %spec.generation,
                source = %response.source, bytes = spec.bytes, child_fd, private_cow,
                "acquired native backing lease; physical sharing still requires target verification");
            Ok(Self {
                file,
                child_fd,
                _lease: stream,
            })
        }

        pub fn child_path(&self) -> PathBuf {
            PathBuf::from(format!("/proc/self/fd/{}", self.child_fd))
        }
    }

    fn receive_fd(stream: &UnixStream) -> Result<OwnedFd> {
        let mut byte = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: 1,
        };
        // usize storage provides cmsghdr alignment. Capacity allows detecting extras.
        let mut control = [0usize; 32];
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
            rc == 1 && byte[0] == b'F' && msg.msg_flags & libc::MSG_CTRUNC == 0 && fds.len() == 1,
            "native provider must pass exactly one non-truncated FD"
        );
        Ok(fds.pop().expect("one checked descriptor"))
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
        };
        assert_eq!(root.boot_arg().unwrap(), "aenv_pmem_rootfs=1");
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
            max_pmem_bytes: PMEM_ALIGNMENT
        }
        .validate()
        .is_err());
    }
}
