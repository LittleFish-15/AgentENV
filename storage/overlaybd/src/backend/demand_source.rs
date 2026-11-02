//! Native preparation of the immutable image's 256 KiB content manifest.
//! This scans the source with O_DIRECT, never allocates UB or creates a device.
use anyhow::Result;
#[cfg(target_os = "linux")]
use anyhow::{ensure, Context};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

#[cfg(target_os = "linux")]
use super::demand_layout::DEVICE_BYTES;
#[cfg(any(target_os = "linux", test))]
use super::demand_layout::LOAD_BYTES;

#[derive(Debug, Serialize, Deserialize)]
pub struct ImageChunk {
    pub index: u64,
    pub offset: u64,
    pub length: u64,
    pub sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageManifest {
    pub version: u32,
    pub layer_digest: String,
    pub file_bytes: u64,
    pub chunk_bytes: u64,
    pub chunks: Vec<ImageChunk>,
}

/// Canonical representation shared with the existing trusted Manifest parser.
fn sorted_json(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let sorted: std::collections::BTreeMap<_, _> =
                map.into_iter().map(|(k, v)| (k, sorted_json(v))).collect();
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(sorted_json).collect())
        }
        other => other,
    }
}

pub fn manifest_digest(manifest: &ImageManifest) -> Result<String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&sorted_json(serde_json::to_value(
            manifest
        )?))?)
    ))
}

#[cfg(target_os = "linux")]
pub fn prepare_image(source: &Path, expected_sha256: &str, output: &Path) -> Result<()> {
    use std::fs::{File, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};

    ensure!(
        source.is_absolute() && source.canonicalize()? == source,
        "unredirected absolute image required"
    );
    ensure!(
        output.is_absolute() && !output.try_exists()?,
        "new absolute manifest output required"
    );
    let parent = output.parent().context("manifest output needs parent")?;
    ensure!(
        parent.canonicalize()? == parent,
        "manifest parent is redirected"
    );
    let expected = expected_sha256
        .strip_prefix("sha256:")
        .unwrap_or(expected_sha256);
    ensure!(
        expected.len() == 64
            && expected
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "trusted lowercase image SHA256 required"
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECT | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(source)?;
    let before = file.metadata()?;
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    ensure!(
        page >= 4096 && LOAD_BYTES.is_multiple_of(page as u64),
        "unsupported direct-read alignment"
    );
    let size = before.len();
    ensure!(
        before.is_file() && size > 0 && size <= DEVICE_BYTES && size.is_multiple_of(page as u64),
        "image must be page-aligned and fit the 4 GiB logical device"
    );
    struct Buffer(*mut libc::c_void);
    impl Drop for Buffer {
        fn drop(&mut self) {
            unsafe { libc::free(self.0) };
        }
    }
    let mut pointer = std::ptr::null_mut();
    ensure!(
        unsafe { libc::posix_memalign(&mut pointer, page as usize, LOAD_BYTES as usize) } == 0,
        "allocate aligned direct-read buffer"
    );
    let buffer = Buffer(pointer);
    let mut whole = Sha256::new();
    let mut chunks = Vec::new();
    for offset in (0..size).step_by(LOAD_BYTES as usize) {
        let length = (size - offset).min(LOAD_BYTES) as usize;
        let data = unsafe { std::slice::from_raw_parts_mut(buffer.0.cast::<u8>(), length) };
        let count = file
            .read_at(data, offset)
            .context("read immutable image with O_DIRECT; no buffered fallback")?;
        ensure!(
            count == length,
            "short direct image read; do not publish manifest"
        );
        whole.update(&*data);
        chunks.push(ImageChunk {
            index: offset / LOAD_BYTES,
            offset,
            length: length as u64,
            sha256: format!("{:x}", Sha256::digest(&*data)),
        });
    }
    let after = file.metadata()?;
    let identity = |m: &std::fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    ensure!(
        identity(&before) == identity(&after),
        "source changed while preparing manifest"
    );
    let digest = format!("{:x}", whole.finalize());
    ensure!(
        digest == expected,
        "source differs from trusted image digest"
    );
    let manifest = ImageManifest {
        version: 1,
        layer_digest: format!("sha256:{digest}"),
        file_bytes: size,
        chunk_bytes: LOAD_BYTES,
        chunks,
    };
    let record = serde_json::json!({"version":1,"document":manifest,
        "sha256":manifest_digest(&manifest)?,"logicalBytes":DEVICE_BYTES,"SDKCalled":false,
        "sourceIdentity":{"device":before.dev(),"inode":before.ino(),"bytes":size,
            "mtimeSeconds":before.mtime(),"mtimeNanos":before.mtime_nsec(),
            "ctimeSeconds":before.ctime(),"ctimeNanos":before.ctime_nsec()}});
    // Create only after all source validation. Existing/incomplete outputs are
    // never overwritten; failure remains visible rather than silently retried.
    let mut target = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(output)?;
    serde_json::to_writer(&mut target, &record)?;
    target.write_all(b"\n")?;
    target.sync_all()?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn prepare_image(_source: &Path, _expected_sha256: &str, _output: &Path) -> Result<()> {
    anyhow::bail!("stable image preparation requires native Linux O_DIRECT")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_manifest_matches_existing_sorted_json_contract() {
        let manifest = ImageManifest {
            version: 1,
            layer_digest: "sha256:abc".into(),
            file_bytes: 4096,
            chunk_bytes: LOAD_BYTES,
            chunks: vec![ImageChunk {
                index: 0,
                offset: 0,
                length: 4096,
                sha256: "def".into(),
            }],
        };
        let canonical = r#"{"chunkBytes":262144,"chunks":[{"index":0,"length":4096,"offset":0,"sha256":"def"}],"fileBytes":4096,"layerDigest":"sha256:abc","version":1}"#;
        assert_eq!(
            manifest_digest(&manifest).unwrap(),
            format!("{:x}", Sha256::digest(canonical.as_bytes()))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn native_direct_manifest_checks_identity_and_never_overwrites() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.img");
        let output = directory.path().join("manifest.json");
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let data = vec![0x53; LOAD_BYTES as usize + page];
        std::fs::write(&source, &data).unwrap();
        std::fs::File::open(&source).unwrap().sync_all().unwrap();
        let digest = format!("{:x}", Sha256::digest(&data));
        prepare_image(&source, &digest, &output).unwrap();
        let saved = std::fs::read(&output).unwrap();
        let record: serde_json::Value = serde_json::from_slice(&saved).unwrap();
        assert_eq!(record["document"]["chunkBytes"], LOAD_BYTES);
        assert_eq!(record["document"]["chunks"].as_array().unwrap().len(), 2);
        assert_eq!(record["document"]["chunks"][1]["length"], page);
        assert_eq!(record["SDKCalled"], false);
        assert!(prepare_image(&source, &digest, &output).is_err());
        assert_eq!(std::fs::read(&output).unwrap(), saved);
        let rejected = directory.path().join("wrong.json");
        assert!(prepare_image(&source, &"0".repeat(64), &rejected).is_err());
        assert!(!rejected.exists());
    }
}
