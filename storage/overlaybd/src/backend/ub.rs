//! Snapshot-layer bytes from a local broker holding a read-only UB import.
//! This feeds the existing ublk/File restore path; it does not map UB into KVM.
use super::ub_protocol::{Session, MAX_CHUNK, MAX_READ};
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
type SessionRegistry = Mutex<HashMap<BrokerKey, Weak<Mutex<Session<UnixStream>>>>>;

#[derive(Hash, PartialEq, Eq)]
struct BrokerKey {
    socket: String,
    object: String,
    generation: String,
    digest: String,
    bytes: u64,
    mapping_bytes: u64,
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
    registry.retain(|_, entry| entry.strong_count() > 0);
    if let Some(session) = registry.get(&key).and_then(Weak::upgrade) {
        if session
            .lock()
            .map_err(|_| anyhow::anyhow!("UB session lock poisoned"))?
            .is_healthy()
        {
            return Ok(session);
        }
    }
    let stream = UnixStream::connect(&replica.broker_socket)
        .context("connect node-local UB layer broker")?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    let session = Arc::new(Mutex::new(
        Session::open(
            stream,
            &replica.object_name,
            &replica.generation,
            &replica.layer_digest,
            replica.file_bytes,
            replica.mapping_bytes,
        )
        .context("open generation-bound UB read lease")?,
    ));
    registry.insert(key, Arc::downgrade(&session));
    Ok(session)
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
}

impl UbLayerFile {
    pub async fn open(replica: &UbLayerRef, fallback_path: Option<PathBuf>) -> Result<Self> {
        replica.validate()?;
        let replica = replica.clone();
        let size = replica.file_bytes;
        let object = replica.object_name.clone();
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
        })
    }
}

#[async_trait]
impl VirtualFile for UbLayerFile {
    async fn read_at(&self, offset: u64, len: usize) -> Result<Bytes> {
        let count = self.size.saturating_sub(offset).min(len as u64) as usize;
        ensure!(
            count <= MAX_READ,
            "UB layer read exceeds bounded allocation limit"
        );
        if count == 0 {
            return Ok(Bytes::new());
        }
        let session = self.session.clone();
        let fallback = self.fallback.clone();
        let fallback_active = Arc::clone(&self.fallback_active);
        tokio::task::spawn_blocking(move || {
            if !fallback_active.load(Ordering::Acquire) {
                let result = session.as_ref().context("missing UB session")?.lock()
                    .map_err(|_| anyhow::anyhow!("UB session lock poisoned"))?.read_at(offset, count);
                match result {
                    Ok(bytes) => return Ok(Bytes::from(bytes)),
                    Err(error) if fallback.is_some() => {
                        if !fallback_active.swap(true, Ordering::AcqRel) {
                            tracing::warn!(%error, resolved_source = "repository", "UB read failed; rereading full range from verified durable source");
                        }
                    }
                    Err(error) => return Err(error).context("read required UB snapshot layer"),
                }
            }
            let mut bytes = vec![0; count];
            fallback.as_ref().context("missing verified UB fallback")?
                .read_exact_at(&mut bytes, offset).context("read entire durable fallback range")?;
            Ok(Bytes::from(bytes))
        })
        .await
        .context("join UB layer read")?
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
            object_name: "jwk_aenv_0123456789abcdef0123456789abcdef".into(),
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
            let mut open = [0; 115]; // exact version1 OPEN after magic/name/identity
            stream.read_exact(&mut open).unwrap();
            assert_eq!(&open[..8], MAGIC);
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
}
