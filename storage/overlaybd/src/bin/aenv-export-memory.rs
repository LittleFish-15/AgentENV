//! Export a complete logical RAM image for a native FD provider. No SDK or VM.
//! GLOBAL_JSON MEMORY_IMAGE_JSON NEW_OUTPUT MAX_BYTES
use anyhow::{ensure, Context, Result};
use overlaybd::config::ImageConfig;
use overlaybd::virtual_file::VirtualFile;
use overlaybd::ImageService;
use sha2::{Digest, Sha256};
use std::path::Path;

#[path = "native_memory/sparse.rs"]
mod sparse;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        args.len() == 4,
        "usage: aenv-export-memory GLOBAL_JSON MEMORY_IMAGE_JSON NEW_OUTPUT MAX_BYTES"
    );
    let config: ImageConfig = serde_json::from_slice(&std::fs::read(&args[1])?)?;
    ensure!(
        config.upper.data.is_empty()
            && config.upper.index.is_empty()
            && config.upper.target.is_empty()
            && config.upper.gzip_index.is_empty(),
        "export requires an immutable memory image"
    );
    ensure!(
        !config.lowers.is_empty()
            && config.lowers.iter().all(|l| l.digest.starts_with("sha256:")
                && l.digest.len() == 71
                && l.size > 0
                && l.digest[7..]
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
        "export requires committed lower identities"
    );
    let service = ImageService::from_config_path(&args[0]).await?;
    let image = service.create_image_file(&args[1]).await?;
    let bytes = image.size().await?;
    let budget: u64 = args[3].parse().context("parse explicit byte budget")?;
    ensure!(
        bytes > 0 && bytes.is_multiple_of(4096) && bytes <= budget,
        "logical RAM image exceeds explicit budget or is not page aligned"
    );
    let output = Path::new(&args[2]);
    ensure!(output.is_absolute(), "output path must be absolute");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(output)
        .context("create new output without overwriting")?;
    let mut digest = Sha256::new();
    let mut offset = 0;
    let mut zero_gap = 0u64;
    while offset < bytes {
        let count = (bytes - offset).min(1024 * 1024) as usize;
        let data = image.read_at(offset, count).await?;
        ensure!(
            data.len() == count,
            "short logical memory read at {offset}; incomplete output retained"
        );
        // Preserve zero-page holes; logical RAM length is not physical allocation.
        sparse::write_pages(&mut file, &data, &mut zero_gap)?;
        digest.update(&data);
        offset += count as u64;
    }
    file.set_len(bytes)?;
    file.sync_all()?;
    #[cfg(unix)]
    let allocated = {
        use std::os::unix::fs::MetadataExt;
        file.metadata()?.blocks().checked_mul(512)
    };
    #[cfg(not(unix))]
    let allocated: Option<u64> = None;
    println!(
        "{}",
        serde_json::json!({"status": "LINEAR_MEMORY_EXPORTED_NO_UB_OR_GUEST",
        "bytes": bytes, "fileAllocatedBytes": allocated,
        "sha256": format!("sha256:{:x}", digest.finalize()), "output": output})
    );
    Ok(())
}
