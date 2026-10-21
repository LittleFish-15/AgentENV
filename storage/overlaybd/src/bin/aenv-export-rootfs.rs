//! Reconstruct an immutable ext4 view from verified local OverlayBD layers.
//! No ublk device, mount, SDK, remote layer fallback or source modification.
use anyhow::{ensure, Context, Result};
use overlaybd::backend::local::LocalFile;
use overlaybd::backend::switch::new_switch_file;
use overlaybd::backend::tar::new_tar_file_adaptor;
use overlaybd::index_file::open_files_ro;
use overlaybd::raw_export::SparseOutput;
use overlaybd::virtual_file::VirtualFile;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Request {
    version: u32,
    source_image: String,
    virtual_bytes: u64,
    max_input_bytes: u64,
    max_written_bytes: u64,
    layers: Vec<Layer>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Layer {
    path: PathBuf,
    digest: String,
    size: u64,
}

#[derive(Serialize)]
struct Identity<'a> {
    digest: &'a str,
    size: u64,
}

fn validate(request: &Request) -> Result<()> {
    ensure!(
        request.version == 1 && !request.layers.is_empty() && request.layers.len() <= 256,
        "unsupported export request"
    );
    ensure!(
        request.virtual_bytes > 0 && request.virtual_bytes.is_multiple_of(4096),
        "invalid logical byte budget"
    );
    ensure!(
        request.max_written_bytes > 0 && request.max_written_bytes <= request.virtual_bytes,
        "invalid written-data budget"
    );
    let mut input_bytes = 0u64;
    for layer in &request.layers {
        ensure!(
            layer.path.is_absolute() && layer.size > 0,
            "local absolute layer path and size required"
        );
        let digest = layer.digest.strip_prefix("sha256:").unwrap_or("");
        ensure!(
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid committed layer digest"
        );
        input_bytes = input_bytes
            .checked_add(layer.size)
            .context("input size overflow")?;
    }
    ensure!(
        input_bytes <= request.max_input_bytes,
        "committed inputs exceed explicit budget"
    );
    let identities: Vec<_> = request
        .layers
        .iter()
        .map(|l| Identity {
            digest: &l.digest,
            size: l.size,
        })
        .collect();
    // Same ordered, path-independent rootfs identity as the Runtime binding.
    let identity = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&(0u64, identities))?)
    );
    ensure!(
        identity == request.source_image,
        "ordered source-image identity differs"
    );
    Ok(())
}

fn stamp(meta: &Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        meta.dev(),
        meta.ino(),
        meta.len(),
        meta.mtime(),
        meta.mtime_nsec(),
        meta.ctime(),
        meta.ctime_nsec(),
    )
}

fn pin_layer(layer: &Layer) -> Result<(File, Metadata)> {
    ensure!(
        layer.path.canonicalize()? == layer.path,
        "redirected layer path"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&layer.path)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file() && before.len() == layer.size,
        "committed input type/length differs"
    );
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    ensure!(
        format!("sha256:{:x}", hash.finalize()) == layer.digest,
        "committed input content digest differs"
    );
    ensure!(
        stamp(&before) == stamp(&file.metadata()?),
        "input changed while hashing"
    );
    Ok((file, before))
}

async fn export(request: Request, output: &Path) -> Result<serde_json::Value> {
    validate(&request)?;
    ensure!(output.is_absolute(), "output directory must be absolute");
    ensure!(
        output
            .parent()
            .context("output parent missing")?
            .canonicalize()?
            == output.parent().unwrap(),
        "output parent redirected"
    );
    let mut pinned = Vec::new();
    for (index, layer) in request.layers.iter().enumerate() {
        pinned.push(pin_layer(layer)?);
        eprintln!("LAYER_VERIFIED index={} bytes={}", index, layer.size);
    }
    // The new private directory and all partial outputs survive an error.
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(output)
        .context("output already exists or cannot be created")?;
    // Prove sparse extension on this output filesystem before setting a large
    // logical length. This does not change a mount or filesystem setting.
    let probe_path = output.join(".sparse-probe");
    let mut probe = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&probe_path)?;
    probe.write_all(&[1])?;
    probe.set_len(2 * 1024 * 1024)?;
    probe.sync_all()?;
    ensure!(
        probe.metadata()?.blocks() <= 128,
        "output filesystem did not preserve sparse extension"
    );
    drop(probe);
    std::fs::remove_file(probe_path)?;
    let mut files: Vec<Arc<dyn VirtualFile>> = Vec::new();
    for (file, _) in &pinned {
        let path = format!("/proc/self/fd/{}", file.as_raw_fd());
        let local: Arc<dyn VirtualFile> = Arc::new(
            LocalFile::builder()
                .write(false)
                .create(false)
                .direct_io(false)
                .open(&path)?,
        );
        let content = new_tar_file_adaptor(local).await?;
        files.push(new_switch_file(content, true, Some(&path)).await?);
    }
    // Use the same local layer decoders and bottom-to-top stack primitive as
    // ImageFile, without a remote backend, mutable upper or index-cache writer.
    let image: Arc<dyn VirtualFile> = Arc::new(open_files_ro(&files).await?);
    let bytes = image.size().await?;
    ensure!(
        bytes == request.virtual_bytes,
        "layer logical size differs from explicit expected size"
    );
    let used = overlaybd::ext4_stat::ext4_used_bytes(&image)
        .await
        .context("input is not a plausible ext4 view")?;
    ensure!(used <= bytes, "ext4 used count exceeds image length");
    let destination = output.join("rootfs.ext4");
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&destination)?;
    let mut sink = SparseOutput::new(file, bytes, request.max_written_bytes);
    let mut hash = Sha256::new();
    let mut progress = Instant::now();
    while sink.logical_bytes() < bytes {
        let offset = sink.logical_bytes();
        let count = (bytes - offset).min(1024 * 1024) as usize;
        let data = image.read_at(offset, count).await?;
        ensure!(
            data.len() == count,
            "short logical read at {offset}; partial output retained"
        );
        sink.append(&data)?;
        hash.update(&data);
        if progress.elapsed() >= Duration::from_secs(5) {
            eprintln!(
                "EXPORT_PROGRESS logical_bytes={} written_bytes={}",
                sink.logical_bytes(),
                sink.written_bytes()
            );
            progress = Instant::now();
        }
    }
    let written = sink.written_bytes();
    let file = sink.into_inner();
    file.set_len(bytes)?;
    file.sync_all()?;
    for (input, before) in &pinned {
        ensure!(
            stamp(before) == stamp(&input.metadata()?),
            "input changed during export"
        );
    }
    let allocated = file
        .metadata()?
        .blocks()
        .checked_mul(512)
        .context("allocated size overflow")?;
    let report = serde_json::json!({
        "status":"RAW_ROOTFS_EXPORTED_NO_UB_OR_GUEST", "sourceImage":request.source_image,
        "virtualBytes":bytes,"dataWrittenBytes":written,"fileAllocatedBytes":allocated,
        "ext4UsedBytesBestEffort":used,"layerCount":request.layers.len(),
        "sha256":format!("sha256:{:x}",hash.finalize()),"output":destination,
        "inputContentHashesVerified":true,"inputMetadataUnchanged":true,
        "SDK_called":false,"ublkDevicesCreated":0,"Guest_created":false,
        "filesystemCompacted":false,"nativeBindingAccepted":false,
        "budgetScope":"Data write bytes; filesystem allocation is separate, not a quota"
    });
    let mut receipt = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(output.join("export.json"))?;
    serde_json::to_writer_pretty(&mut receipt, &report)?;
    receipt.sync_all()?;
    Ok(report)
}

#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        args.len() == 2,
        "usage: aenv-export-rootfs REQUEST_JSON NEW_OUTPUT_DIRECTORY"
    );
    let mut input = Vec::new();
    File::open(&args[0])?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut input)?;
    ensure!(input.len() <= 1024 * 1024, "request exceeds 1 MiB");
    let request: Request = serde_json::from_slice(&input)?;
    println!("{}", export(request, Path::new(&args[1])).await?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> Request {
        let layers = vec![Layer {
            path: "/local/layer".into(),
            digest: format!("sha256:{}", "a".repeat(64)),
            size: 4096,
        }];
        let ids: Vec<_> = layers
            .iter()
            .map(|l| Identity {
                digest: &l.digest,
                size: l.size,
            })
            .collect();
        Request {
            version: 1,
            source_image: format!(
                "sha256:{:x}",
                Sha256::digest(serde_json::to_vec(&(0u64, ids)).unwrap())
            ),
            virtual_bytes: 8192,
            max_input_bytes: 4096,
            max_written_bytes: 4096,
            layers,
        }
    }
    #[test]
    fn identity_and_limits_are_enforced() {
        validate(&request()).unwrap();
        let mut value = request();
        value.source_image = format!("sha256:{}", "0".repeat(64));
        assert!(validate(&value).is_err());
        let mut value = request();
        value.layers[0].size += 1;
        assert!(validate(&value).is_err());
        let mut value = request();
        value.max_written_bytes = 16384;
        assert!(validate(&value).is_err());
        let mut value = request();
        value.layers[0].path = "https://invalid/layer".into();
        assert!(validate(&value).is_err());
    }
    #[test]
    fn mutable_or_remote_fields_are_not_accepted() {
        assert!(serde_json::from_str::<Request>(r#"{"version":1,"sourceImage":"x","virtualBytes":4096,"maxInputBytes":4096,"maxWrittenBytes":4096,"layers":[],"upper":{"data":"/tmp/rw"}}"#).is_err());
    }

    #[tokio::test]
    async fn stacked_export_preserves_overrides_and_zero_pages() -> Result<()> {
        use overlaybd::backend::local::LocalFile;
        use overlaybd::index_file::LSMTFile;
        let temp = tempfile::tempdir()?;
        let virtual_bytes = 2 * 1024 * 1024;
        let mut expected = vec![0u8; virtual_bytes as usize];
        // A minimal plausible ext4 superblock for the export usage probe.
        expected[1024 + 0x38..1024 + 0x3a].copy_from_slice(&0xEF53u16.to_le_bytes());
        expected[1024 + 0x18..1024 + 0x1c].copy_from_slice(&2u32.to_le_bytes());
        expected[1024 + 0x04..1024 + 0x08].copy_from_slice(&512u32.to_le_bytes());
        expected[1024 + 0x0c..1024 + 0x10].copy_from_slice(&500u32.to_le_bytes());
        let mut layers = Vec::new();
        for index in 0..2 {
            let path = temp.path().join(format!("layer-{index}.commit"));
            let file: Arc<dyn VirtualFile> = Arc::new(LocalFile::new(&path)?);
            let writable = LSMTFile::create(file, None, virtual_bytes, true).await?;
            if index == 0 {
                writable.write_at(0, &expected[..4096]).await?;
                writable.write_at(4096, &[7; 8192]).await?;
            } else {
                writable.write_at(4096, &[9; 4096]).await?;
                writable.write_at(8192, &[0; 4096]).await?;
            }
            writable.close_seal().await?;
            drop(writable);
            let data = std::fs::read(&path)?;
            layers.push(Layer {
                path: path.canonicalize()?,
                digest: format!("sha256:{:x}", Sha256::digest(&data)),
                size: data.len() as u64,
            });
        }
        expected[4096..8192].fill(9);
        let identities: Vec<_> = layers
            .iter()
            .map(|l| Identity {
                digest: &l.digest,
                size: l.size,
            })
            .collect();
        let source_image = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&(0u64, identities))?)
        );
        let request = Request {
            version: 1,
            source_image,
            virtual_bytes,
            max_input_bytes: 16 * 1024 * 1024,
            max_written_bytes: 8192,
            layers,
        };
        let output = temp.path().join("exported");
        let report = export(request, &output).await?;
        assert_eq!(std::fs::read(output.join("rootfs.ext4"))?, expected);
        assert_eq!(report["dataWrittenBytes"], 8192);
        assert_eq!(report["virtualBytes"], virtual_bytes);
        assert_eq!(
            report["sha256"],
            format!("sha256:{:x}", Sha256::digest(&expected))
        );
        Ok(())
    }
}
