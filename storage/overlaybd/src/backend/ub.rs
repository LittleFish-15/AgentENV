//! Snapshot-layer bytes from a local broker holding a read-only UB import.
//! This feeds the existing ublk/File restore path; it does not map UB into KVM.
use super::ub_protocol::{Session, SessionHealth, MAX_CHUNK, MAX_READ};
use crate::config::UbLayerRef;
use crate::io::virtual_file::VirtualFile;
use anyhow::{bail, ensure, Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::os::unix::fs::FileExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

type SharedSession = Arc<Mutex<Session<UnixStream>>>;
type SessionRegistry = Mutex<HashMap<BrokerKey, RegistryEntry>>;

struct RegistryEntry {
    session: Weak<Mutex<Session<UnixStream>>>,
    health: SessionHealth,
}

#[derive(Hash, PartialEq, Eq)]
struct BrokerKey {
    socket: String,
    object: String,
    generation: String,
    digest: String,
    bytes: u64,
    mapping_bytes: u64,
}

#[cfg(target_os = "linux")]
fn verify_broker_peer(stream: &UnixStream) -> Result<u32> {
    use std::os::fd::AsRawFd;
    let mut peer = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SO_PEERCRED writes a complete ucred on success; validate its length
    // before reading it. No credentials supplied in the payload are trusted.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            peer.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("read UB broker peer credentials");
    }
    ensure!(
        length as usize == std::mem::size_of::<libc::ucred>(),
        "short UB broker peer credentials"
    );
    let peer = unsafe { peer.assume_init() };
    ensure!(
        peer.uid == unsafe { libc::geteuid() } && peer.pid > 0,
        "UB broker must run as the same runtime UID"
    );
    Ok(peer.pid as u32)
}

#[cfg(not(target_os = "linux"))]
fn verify_broker_peer(_stream: &UnixStream) -> Result<u32> {
    bail!("UB broker peer verification requires Linux")
}

fn acquire_session(replica: &UbLayerRef) -> Result<SharedSession> {
    static SESSIONS: OnceLock<SessionRegistry> = OnceLock::new();
    let key = BrokerKey {
        socket: replica.broker_socket.clone(),
        object: replica.object_name.clone(),
        generation: replica.generation.clone(),
        digest: replica.layer_digest.clone(),
        bytes: replica.file_bytes,
        mapping_bytes: replica.mapping_bytes,
    };
    let mut registry = SESSIONS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|_| anyhow::anyhow!("UB session registry poisoned"))?;
    // A failed incarnation remains poisoned after its last reader disappears.
    // A later Guest must not silently reconnect to the same unknown outcome.
    registry.retain(|_, entry| !entry.health.is_healthy() || entry.session.strong_count() > 0);
    if let Some(entry) = registry.get(&key) {
        ensure!(
            entry.health.is_healthy(),
            "UB incarnation previously failed; explicit recovery required"
        );
    }
    if let Some(session) = registry.get(&key).and_then(|entry| entry.session.upgrade()) {
        ensure!(
            session
                .lock()
                .map_err(|_| anyhow::anyhow!("UB session lock poisoned"))?
                .is_healthy(),
            "live UB incarnation has a failed read lease; implicit reconnect refused"
        );
        return Ok(session);
    }
    ensure!(
        registry.len() < 4096,
        "UB incarnation registry full; failed entries cannot be silently evicted"
    );
    let stream = UnixStream::connect(&replica.broker_socket)
        .context("connect node-local UB layer broker")?;
    let broker_pid = verify_broker_peer(&stream)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    let connection = Session::open(
        stream,
        &replica.object_name,
        &replica.generation,
        &replica.layer_digest,
        replica.file_bytes,
        replica.mapping_bytes,
    )
    .context("open generation-bound UB read lease")?;
    let health = connection.health_token();
    tracing::info!(target: "aenv::ub_lease", object = %replica.object_name,
        generation = %replica.generation, broker_pid, bytes = replica.file_bytes,
        "generation-bound UB read permit accepted");
    let session = Arc::new(Mutex::new(connection));
    registry.insert(
        key,
        RegistryEntry {
            session: Arc::downgrade(&session),
            health,
        },
    );
    Ok(session)
}

/// Runtime-side read permits held until its private rootfs device is deleted.
/// The daemon also owns its own read sessions. Neither side can retire a base
/// while another Guest or an in-flight daemon read still holds a connection.
pub struct RuntimeReadLeases {
    replicas: Vec<UbLayerRef>,
    _sessions: Vec<SharedSession>,
}

impl RuntimeReadLeases {
    pub fn acquire(image_path: &std::path::Path) -> Result<Option<Self>> {
        let image = crate::config::load_image_config(image_path)?;
        let required = image.lowers.iter().any(|layer| {
            layer
                .ub
                .as_ref()
                .is_some_and(|replica| !replica.allow_repository_fallback)
        });
        if !required {
            return Ok(None);
        }
        let mut replicas = Vec::new();
        let mut sessions = Vec::new();
        for layer in image.lowers {
            let replica = layer
                .ub
                .context("required UB rootfs has an unbound lower")?;
            ensure!(
                !replica.allow_repository_fallback,
                "required UB rootfs cannot mix fallback layers"
            );
            replica.validate()?;
            ensure!(
                replica.layer_digest == layer.digest && replica.file_bytes == layer.size,
                "UB rootfs read permit differs from committed lower"
            );
            sessions.push(acquire_session(&replica)?);
            replicas.push(replica);
        }
        Ok(Some(Self {
            replicas,
            _sessions: sessions,
        }))
    }

    pub fn replicas(&self) -> &[UbLayerRef] {
        &self.replicas
    }

    pub fn verify_runtime_image(&self, image_path: &std::path::Path) -> Result<()> {
        let image = crate::config::load_image_config(image_path)?;
        ensure!(
            image.lowers.len() == self.replicas.len(),
            "created rootfs device lost required UB lowers"
        );
        for (layer, expected) in image.lowers.iter().zip(&self.replicas) {
            ensure!(
                layer.ub.as_ref() == Some(expected)
                    && layer.digest == expected.layer_digest
                    && layer.size == expected.file_bytes,
                "created rootfs device changed its UB binding"
            );
        }
        Ok(())
    }
}

/// Preserve an ancestor's exact stored bytes when a new durable snapshot is
/// committed on a node that only imported its UB replica. Call after capture,
/// with a newly created temporary file; never overwrite an existing artifact.
pub fn copy_verified_stored_layer(replica: &UbLayerRef, destination: &mut File) -> Result<()> {
    replica.validate()?;
    ensure!(
        destination.metadata()?.len() == 0 && destination.stream_position()? == 0,
        "UB durable export requires a new empty temporary file"
    );
    let session = acquire_session(replica)?;
    let mut digest = Sha256::new();
    let mut offset = 0;
    while offset < replica.file_bytes {
        let count = (replica.file_bytes - offset).min(MAX_CHUNK as u64) as usize;
        let bytes = session
            .lock()
            .map_err(|_| anyhow::anyhow!("UB export session poisoned"))?
            .read_at(offset, count)?;
        ensure!(
            bytes.len() == count,
            "UB durable export returned a short stored range"
        );
        digest.update(&bytes);
        destination.write_all(&bytes)?;
        offset += bytes.len() as u64;
    }
    ensure!(
        format!("sha256:{:x}", digest.finalize()) == replica.layer_digest,
        "UB durable export differs from the committed stored layer identity"
    );
    destination.sync_all()?;
    Ok(())
}

pub struct UbLayerFile {
    session: Option<SharedSession>,
    fallback: Option<Arc<File>>,
    fallback_active: Arc<AtomicBool>,
    size: u64,
    object: String,
    generation: String,
    #[cfg(feature = "rootfs-read-trace")]
    digest: String,
}

impl UbLayerFile {
    pub async fn open(replica: &UbLayerRef, fallback_path: Option<PathBuf>) -> Result<Self> {
        replica.validate()?;
        let replica = replica.clone();
        let size = replica.file_bytes;
        #[cfg(feature = "rootfs-read-trace")]
        let digest = replica.layer_digest.clone();
        let object = replica.object_name.clone();
        let generation = replica.generation.clone();
        let fallback_replica = replica.clone();
        let fallback = if replica.allow_repository_fallback {
            let path = fallback_path
                .context("UB repository fallback requires a local durable layer file")?;
            Some(Arc::new(
                tokio::task::spawn_blocking(move || -> Result<File> {
                    let mut file = File::open(path).context("open durable UB fallback")?;
                    ensure!(
                        file.metadata()?.len() == fallback_replica.file_bytes,
                        "UB fallback stored length differs"
                    );
                    let mut digest = Sha256::new();
                    let mut buffer = vec![0; 1024 * 1024];
                    loop {
                        let count = file.read(&mut buffer)?;
                        if count == 0 {
                            break;
                        }
                        digest.update(&buffer[..count]);
                    }
                    ensure!(
                        format!("sha256:{:x}", digest.finalize()) == fallback_replica.layer_digest,
                        "UB fallback is not the same immutable stored layer"
                    );
                    Ok(file)
                })
                .await
                .context("join fallback identity verification")??,
            ))
        } else {
            None
        };
        let session_result = tokio::task::spawn_blocking(move || acquire_session(&replica))
            .await
            .context("join UB layer open")?;
        let (session, degraded) = match session_result {
            Ok(session) => (Some(session), false),
            Err(error) if fallback.is_some() => {
                tracing::warn!(%object, %error, resolved_source = "repository", "UB layer open degraded to verified durable source");
                (None, true)
            }
            Err(error) => return Err(error),
        };
        tracing::info!(%object, bytes = size, mode = "ub_snapshot_layers_local_cow",
                       resolved_source = if degraded { "repository" } else { "ub" }, "opened snapshot layer");
        Ok(Self {
            session,
            fallback,
            fallback_active: Arc::new(AtomicBool::new(degraded)),
            size,
            object,
            generation,
            #[cfg(feature = "rootfs-read-trace")]
            digest,
        })
    }
}

impl UbLayerFile {
    async fn read_range(&self, offset: u64, len: usize) -> Result<(Bytes, bool)> {
        let count = self.size.saturating_sub(offset).min(len as u64) as usize;
        ensure!(
            count <= MAX_READ,
            "UB layer read exceeds bounded allocation limit"
        );
        if count == 0 {
            return Ok((Bytes::new(), false));
        }
        let session = self.session.clone();
        let fallback = self.fallback.clone();
        let fallback_active = Arc::clone(&self.fallback_active);
        let object = self.object.clone();
        let generation = self.generation.clone();
        tokio::task::spawn_blocking(move || {
            if !fallback_active.load(Ordering::Acquire) {
                let result = session.as_ref().context("missing UB session")?.lock()
                    .map_err(|_| anyhow::anyhow!("UB session lock poisoned"))?.read_at(offset, count);
                match result {
                    Ok(bytes) => {
                        metrics::counter!("overlaybd_ub_read_requests_total").increment(1);
                        metrics::counter!("overlaybd_ub_read_bytes_total").increment(bytes.len() as u64);
                        tracing::debug!(target: "aenv::ub_read", %object, %generation,
                            offset, bytes = bytes.len(), resolved_source = "ub", "UB lower read completed");
                        return Ok((Bytes::from(bytes), true));
                    }
                    Err(error) if fallback.is_some() => {
                        if !fallback_active.swap(true, Ordering::AcqRel) {
                            tracing::warn!(%error, resolved_source = "repository", "UB read failed; rereading full range from verified durable source");
                        }
                    }
                    Err(error) => {
                        metrics::counter!("overlaybd_ub_read_errors_total").increment(1);
                        tracing::error!(target: "aenv::ub_read", %object, %generation, offset, count,
                            %error, "required UB read failed; no local fallback");
                        return Err(error).context("read required UB snapshot layer");
                    }
                }
            }
            let mut bytes = vec![0; count];
            fallback.as_ref().context("missing verified UB fallback")?
                .read_exact_at(&mut bytes, offset).context("read entire durable fallback range")?;
            Ok((Bytes::from(bytes), false))
        })
        .await
        .context("join UB layer read")?
    }
}

#[async_trait]
impl VirtualFile for UbLayerFile {
    async fn read_at(&self, offset: u64, len: usize) -> Result<Bytes> {
        self.read_range(offset, len).await.map(|(bytes, _)| bytes)
    }

    #[cfg(feature = "io-uring")]
    fn read_at_with_ctx<'a>(
        &'a self,
        ctx: crate::io::virtual_file::IoCtx<'a>,
        offset: u64,
        len: usize,
    ) -> crate::io::virtual_file::LocalBoxFuture<'a, Result<Bytes>> {
        Box::pin(async move {
            #[cfg(feature = "rootfs-read-trace")]
            let started = crate::rootfs_access_trace::now_ns();
            #[cfg(feature = "rootfs-read-trace")]
            let observation = crate::rootfs_access_trace::begin_read(ctx.read_source());
            let result = self.read_range(offset, len).await;
            #[cfg(feature = "rootfs-read-trace")]
            if let (Some(source), Ok((data, from_ub))) = (ctx.read_source(), &result) {
                crate::rootfs_access_trace::record_content(
                    source,
                    &self.digest,
                    self.size,
                    offset,
                    data.len(),
                    *from_ub,
                    started,
                );
            }
            #[cfg(feature = "rootfs-read-trace")]
            crate::rootfs_access_trace::finish_read(observation, result.is_ok());
            #[cfg(not(feature = "rootfs-read-trace"))]
            let _ = ctx;
            result.map(|(bytes, _)| bytes)
        })
    }

    async fn write_at(&self, _offset: u64, _data: &[u8]) -> Result<usize> {
        bail!("UB snapshot layers are read-only; writes belong to the instance's local upper")
    }

    async fn size(&self) -> Result<u64> {
        Ok(self.size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::ub_protocol::MAGIC;
    use std::net::Shutdown;
    use std::os::unix::net::UnixListener;

    fn replica(directory: &std::path::Path, bytes: &[u8], fallback: bool) -> UbLayerRef {
        UbLayerRef {
            broker_socket: directory.join("b.sock").to_string_lossy().into_owned(),
            object_name: "aenv_0123456789abcdef0123456789abcdef".into(),
            generation: "0123456789abcdef0123456789abcdef".into(),
            layer_digest: format!("sha256:{:x}", Sha256::digest(bytes)),
            file_bytes: bytes.len() as u64,
            mapping_bytes: 4 * 1024 * 1024,
            allow_repository_fallback: fallback,
        }
    }

    fn response(stream: &mut UnixStream, count: usize) -> Result<()> {
        stream.write_all(MAGIC)?;
        stream.write_all(&0u32.to_be_bytes())?;
        stream.write_all(&(count as u32).to_be_bytes())?;
        Ok(())
    }

    /// A wire fault injector, not an SDK substitute: actual SDK tests are separate.
    fn serve_once(path: &str, data: Vec<u8>, fail_second: bool) -> std::thread::JoinHandle<usize> {
        let listener = UnixListener::bind(path).unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            // OPEN is magic + u16 name length + name + generation + two
            // u64 lengths + digest. Read the framing before its payload;
            // waiting for extra bytes deadlocks against the client's ACK wait.
            let mut header = [0; 10];
            stream.read_exact(&mut header).unwrap();
            assert_eq!(&header[..8], MAGIC);
            let name_len = u16::from_be_bytes(header[8..10].try_into().unwrap()) as usize;
            assert_eq!(name_len, 37);
            let mut identity = vec![0; name_len + 16 + 8 + 8 + 32];
            stream.read_exact(&mut identity).unwrap();
            assert_eq!(&identity[..name_len], b"aenv_0123456789abcdef0123456789abcdef");
            response(&mut stream, 0).unwrap();
            let mut requests = 0;
            loop {
                let mut request = [0; 12];
                if stream.read_exact(&mut request).is_err() {
                    break;
                }
                let offset = u64::from_be_bytes(request[..8].try_into().unwrap()) as usize;
                let count = u32::from_be_bytes(request[8..].try_into().unwrap()) as usize;
                requests += 1;
                response(&mut stream, count).unwrap();
                if fail_second && requests == 2 {
                    stream.write_all(&[0xff]).unwrap();
                    stream.shutdown(Shutdown::Both).unwrap();
                    break;
                }
                if fail_second {
                    stream.write_all(&vec![0xff; count]).unwrap();
                } else {
                    stream.write_all(&data[offset..offset + count]).unwrap();
                }
            }
            requests
        })
    }

    #[tokio::test]
    async fn required_ub_does_not_silently_use_an_existing_local_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("layer");
        std::fs::write(&path, b"data").unwrap();
        assert!(
            UbLayerFile::open(&replica(directory.path(), b"data", false), Some(path))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn explicit_fallback_verifies_identity_and_is_readonly() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("layer");
        std::fs::write(&path, b"data").unwrap();
        let reference = replica(directory.path(), b"data", true);
        let file = UbLayerFile::open(&reference, Some(path.clone()))
            .await
            .unwrap();
        assert_eq!(file.read_at(0, 20).await.unwrap().as_ref(), b"data");
        assert!(file.read_at(4, 20).await.unwrap().is_empty());
        assert!(file.write_at(0, b"x").await.is_err());
        let wrong = replica(directory.path(), b"else", true);
        assert!(UbLayerFile::open(&wrong, Some(path)).await.is_err());
    }

    #[tokio::test]
    async fn failed_second_chunk_rereads_the_entire_verified_fallback_range() {
        let directory = tempfile::tempdir().unwrap();
        let bytes = vec![0x42; MAX_CHUNK + 17];
        let path = directory.path().join("layer");
        std::fs::write(&path, &bytes).unwrap();
        let reference = replica(directory.path(), &bytes, true);
        let server = serve_once(&reference.broker_socket, bytes.clone(), true);
        let file = UbLayerFile::open(&reference, Some(path)).await.unwrap();
        assert_eq!(file.read_at(0, bytes.len()).await.unwrap().as_ref(), bytes);
        assert_eq!(file.read_at(12, 17).await.unwrap().as_ref(), [0x42; 17]);
        drop(file);
        assert_eq!(server.join().unwrap(), 2);
    }

    #[tokio::test]
    async fn shared_session_holds_readers_and_exports_exact_durable_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let bytes = b"immutable ancestor".to_vec();
        let reference = replica(directory.path(), &bytes, false);
        let server = serve_once(&reference.broker_socket, bytes.clone(), false);
        let first = UbLayerFile::open(&reference, None).await.unwrap();
        let second = UbLayerFile::open(&reference, None).await.unwrap();
        assert_eq!(first.read_at(0, bytes.len()).await.unwrap().as_ref(), bytes);
        drop(first);
        assert_eq!(
            second.read_at(0, bytes.len()).await.unwrap().as_ref(),
            bytes
        );
        let mut output = tempfile::tempfile().unwrap();
        copy_verified_stored_layer(&reference, &mut output).unwrap();
        assert!(copy_verified_stored_layer(&reference, &mut output).is_err());
        output.rewind().unwrap();
        let mut exported = Vec::new();
        output.read_to_end(&mut exported).unwrap();
        assert_eq!(exported, bytes);
        drop(second);
        assert_eq!(server.join().unwrap(), 3);
    }

    #[tokio::test]
    async fn failed_incarnation_cannot_reconnect_even_after_last_file_drops() {
        let directory = tempfile::tempdir().unwrap();
        let bytes = vec![0x42; MAX_CHUNK + 17];
        let reference = replica(directory.path(), &bytes, false);
        let server = serve_once(&reference.broker_socket, bytes, true);
        let first = UbLayerFile::open(&reference, None).await.unwrap();
        assert!(first.read_at(0, MAX_CHUNK + 17).await.is_err());
        assert!(UbLayerFile::open(&reference, None).await.is_err());
        drop(first);
        assert_eq!(server.join().unwrap(), 2);
        let error = acquire_session(&reference).err().unwrap();
        assert!(error.to_string().contains("explicit recovery"));
    }

    #[tokio::test]
    async fn runtime_permits_outlive_one_guest_and_keep_broker_session_open() {
        let directory = tempfile::tempdir().unwrap();
        let bytes = b"shared immutable lower".to_vec();
        let reference = replica(directory.path(), &bytes, false);
        let image = crate::config::ImageConfig {
            lowers: vec![crate::config::LayerConfig {
                ub: Some(reference.clone()),
                digest: reference.layer_digest.clone(),
                size: reference.file_bytes,
                ..Default::default()
            }],
            ..Default::default()
        };
        let path = directory.path().join("image.json");
        std::fs::write(&path, serde_json::to_vec(&image).unwrap()).unwrap();
        let server = serve_once(&reference.broker_socket, bytes.clone(), false);
        let one = RuntimeReadLeases::acquire(&path).unwrap().unwrap();
        let two = RuntimeReadLeases::acquire(&path).unwrap().unwrap();
        assert_eq!(one.replicas(), std::slice::from_ref(&reference));
        one.verify_runtime_image(&path).unwrap();
        let mut changed = image.clone();
        changed.lowers[0].ub.as_mut().unwrap().generation = "f".repeat(32);
        std::fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(one.verify_runtime_image(&path).is_err());
        std::fs::write(&path, serde_json::to_vec(&image).unwrap()).unwrap();
        drop(one);
        let file = UbLayerFile::open(&reference, None).await.unwrap();
        assert_eq!(file.read_at(0, bytes.len()).await.unwrap().as_ref(), bytes);
        drop(file);
        assert!(!server.is_finished());
        drop(two);
        assert_eq!(server.join().unwrap(), 1);
    }
}
