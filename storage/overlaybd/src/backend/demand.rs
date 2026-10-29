//! Actual VirtualFile implementation for explicitly enabled demand-backed lowers.
use super::demand_protocol::Session;
use crate::config::DemandLayerRef;
use crate::io::virtual_file::VirtualFile;
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct DemandLayerFile {
    session: Arc<Mutex<Session<UnixStream>>>,
    size: u64,
    #[cfg(feature = "rootfs-read-trace")]
    digest: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;

    // The Unix service is a test double, not UB/DAX. This exercises the actual
    // VirtualFile adapter and its blocking transport, beyond Session unit tests.
    #[tokio::test]
    async fn actual_virtual_file_uses_demand_wire_and_rejects_writes() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("d.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut handshake = [0_u8; 143];
            stream.read_exact(&mut handshake).unwrap();
            assert_eq!(&handshake[..8], super::super::demand_protocol::MAGIC);
            let mut response = [0_u8; 24];
            response[..8].copy_from_slice(super::super::demand_protocol::MAGIC);
            stream.write_all(&response).unwrap();
            let mut request = [0_u8; 20];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(u64::from_be_bytes(request[..8].try_into().unwrap()), 1);
            assert_eq!(u64::from_be_bytes(request[8..16].try_into().unwrap()), 7);
            assert_eq!(u32::from_be_bytes(request[16..].try_into().unwrap()), 3);
            response[12..16].copy_from_slice(&3_u32.to_be_bytes());
            response[16..24].copy_from_slice(&1_u64.to_be_bytes());
            stream.write_all(&response).unwrap();
            stream.write_all(b"xyz").unwrap();
        });
        let reference = DemandLayerRef {
            broker_socket: socket.to_str().unwrap().to_owned(),
            object_name: format!("aenv_{}", "b".repeat(32)),
            generation: "c".repeat(32),
            layer_digest: format!("sha256:{}", "d".repeat(64)),
            file_bytes: 4096,
            logical_wire_bytes: 4 * 1024 * 1024,
            manifest_sha256: format!("sha256:{}", "e".repeat(64)),
            request_timeout_ms: 1000,
        };
        let file: Arc<dyn VirtualFile> = Arc::new(DemandLayerFile::open(&reference).await.unwrap());
        assert_eq!(file.size().await.unwrap(), 4096);
        assert_eq!(file.read_at(7, 3).await.unwrap().as_ref(), b"xyz");
        assert!(file.write_at(0, b"x").await.is_err());
        server.join().unwrap();
    }
}

impl DemandLayerFile {
    pub async fn open(reference: &DemandLayerRef) -> Result<Self> {
        reference.validate()?;
        let reference = reference.clone();
        let size = reference.file_bytes;
        #[cfg(feature = "rootfs-read-trace")]
        let digest = reference.layer_digest.clone();
        let session = tokio::task::spawn_blocking(move || -> Result<_> {
            let stream = UnixStream::connect(&reference.broker_socket).context("connect required demand broker")?;
            let timeout = Duration::from_millis(reference.request_timeout_ms);
            stream.set_read_timeout(Some(timeout))?;
            stream.set_write_timeout(Some(timeout))?;
            Session::open(stream, &reference.object_name, &reference.generation, &reference.layer_digest,
                          reference.file_bytes, reference.logical_wire_bytes, &reference.manifest_sha256)
                .context("open metadata-only demand layer")
        }).await.context("join demand layer open")??;
        Ok(Self { session: Arc::new(Mutex::new(session)), size,
                  #[cfg(feature = "rootfs-read-trace")] digest })
    }

    async fn read_range(&self, offset: u64, len: usize) -> Result<Bytes> {
        let session = Arc::clone(&self.session);
        tokio::task::spawn_blocking(move || {
            session.lock().map_err(|_| anyhow::anyhow!("demand session lock poisoned"))?
                .read_at(offset, len).map(Bytes::from).context("required demand lower read failed")
        }).await.context("join demand lower read")?
    }
}

#[async_trait]
impl VirtualFile for DemandLayerFile {
    async fn read_at(&self, offset: u64, len: usize) -> Result<Bytes> {
        self.read_range(offset, len).await
    }

    #[cfg(feature = "io-uring")]
    fn read_at_with_ctx<'a>(&'a self, ctx: crate::io::virtual_file::IoCtx<'a>, offset: u64, len: usize)
        -> crate::io::virtual_file::LocalBoxFuture<'a, Result<Bytes>> {
        Box::pin(async move {
            #[cfg(feature = "rootfs-read-trace")]
            let started = crate::rootfs_access_trace::now_ns();
            #[cfg(feature = "rootfs-read-trace")]
            let observation = crate::rootfs_access_trace::begin_read(ctx.read_source());
            let result = self.read_range(offset, len).await;
            #[cfg(feature = "rootfs-read-trace")]
            if let (Some(source), Ok(data)) = (ctx.read_source(), &result) {
                crate::rootfs_access_trace::record_content(source, &self.digest, self.size,
                    offset, data.len(), true, started);
            }
            #[cfg(feature = "rootfs-read-trace")]
            crate::rootfs_access_trace::finish_read(observation, result.is_ok());
            #[cfg(not(feature = "rootfs-read-trace"))]
            let _ = ctx;
            result
        })
    }

    async fn write_at(&self, _offset: u64, _data: &[u8]) -> Result<usize> {
        bail!("demand lower is immutable; writes belong to the private upper")
    }
    async fn size(&self) -> Result<u64> { Ok(self.size) }
}
