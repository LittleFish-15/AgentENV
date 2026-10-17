//! Small stored-format/local-CoW probe. No VM, ublk device or service changes.
//! `prepare NEW_DIR`, then `check IMAGE_JSON REPLICA_INDEX NEW_OUTPUT_DIR`.
use anyhow::{bail, ensure, Context, Result};
use overlaybd::backend::{local::LocalFile, tar::new_tar_file_create};
use overlaybd::config::{self, DownloadConfig, ImageConfig, LayerConfig, UpperConfig, UpperMode};
use overlaybd::index_file::{create_file_rw, LayerInfo};
use overlaybd::virtual_file::VirtualFile;
use overlaybd::zfile::{zfile_compress, CompressArgs, CompressOptions};
use overlaybd::{ImageFile, ImageService};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn new_directory(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute(),
        "probe needs an absolute new output directory"
    );
    std::fs::create_dir(path).context("create new probe directory without replacing prior data")
}

fn write_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    std::fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn global_config(directory: &Path) -> Result<PathBuf> {
    let path = directory.join("overlaybd.json");
    write_json(
        &path,
        &json!({
            "registryFsVersion": "v2", "ioEngine": 0,
            "cacheConfig": {"cacheType": "file", "cacheDir": directory.join("cache"),
                            "cacheSizeGB": 1, "refillSize": 262144, "blockSize": 65536},
            "download": DownloadConfig::default()
        }),
    )?;
    Ok(path)
}

async fn prepare(directory: &Path) -> Result<()> {
    new_directory(directory)?;
    let data: Arc<dyn VirtualFile> = Arc::new(LocalFile::new(directory.join("raw.commit"))?);
    let index: Arc<dyn VirtualFile> = Arc::new(LocalFile::new(directory.join("raw.index"))?);
    let layer = create_file_rw(LayerInfo::new(data, Some(index), 8192)).await?;
    layer.write_at(0, &vec![0x11; 8192]).await?;
    layer.close_seal().await?;
    drop(layer);
    let stored = std::fs::read(directory.join("raw.commit"))?;
    let tar = new_tar_file_create(Arc::new(LocalFile::new(directory.join("tar.commit"))?)).await?;
    ensure!(
        tar.write_at(0, &stored).await? == stored.len(),
        "short tar fixture write"
    );
    tar.close().await?;
    let tar =
        new_tar_file_create(Arc::new(LocalFile::new(directory.join("zfile.commit"))?)).await?;
    let source: Arc<dyn VirtualFile> = Arc::new(LocalFile::open_ro(directory.join("raw.commit"))?);
    zfile_compress(
        source,
        tar.clone(),
        &CompressArgs {
            opt: CompressOptions::new(CompressOptions::LZ4, 4096, 1),
            overwrite_header: false,
            workers: 1,
        },
    )
    .await?;
    tar.close().await?;
    for format in ["raw", "tar", "zfile"] {
        let file = directory.join(format!("{format}.commit"));
        let bytes = std::fs::read(&file)?;
        let image = ImageConfig {
            lowers: vec![LayerConfig {
                file: file.to_string_lossy().into_owned(),
                digest: format!("sha256:{:x}", Sha256::digest(&bytes)),
                size: bytes.len() as u64,
                ..Default::default()
            }],
            ..Default::default()
        };
        write_json(&directory.join(format!("{format}-image.json")), &image)?;
    }
    println!(
        "{}",
        json!({"status": "UB_LAYER_FIXTURES_PREPARED_NO_SDK",
        "directory": directory, "virtual_bytes": 8192, "formats": ["raw", "tar", "zfile"]})
    );
    Ok(())
}

async fn check(image: &Path, replicas: &Path, output: &Path) -> Result<()> {
    new_directory(output)?;
    let mut cfg = config::load_image_config(image)?;
    config::bind_ub_layer_replicas(&mut cfg, replicas)?;
    config::validate_image_config(&cfg)?;
    ensure!(
        cfg.lowers.len() == 1 && cfg.lowers[0].ub.is_some(),
        "use one small prepared format per probe"
    );
    ensure!(
        !cfg.lowers[0].ub.as_ref().unwrap().allow_repository_fallback,
        "acceptance requires UB, with repository fallback disabled"
    );
    let service = ImageService::from_config_path(global_config(output)?).await?;
    let base = ImageFile::open(cfg.clone(), service.clone(), None).await?;
    ensure!(
        base.read_at(0, 8192).await?.as_ref() == [0x11; 8192],
        "wrong base fixture bytes"
    );
    let mut images = Vec::new();
    for name in ["instance-a", "instance-b"] {
        let mut private = cfg.clone();
        let data = output.join(format!("{name}.data"));
        let index = output.join(format!("{name}.index"));
        overlaybd::helper::prepare_runtime_upper(
            &data,
            Some(&index),
            8192,
            UpperMode::LogStructured,
        )?;
        private.upper = UpperConfig {
            data: data.to_string_lossy().into_owned(),
            index: index.to_string_lossy().into_owned(),
            ..Default::default()
        };
        images.push(ImageFile::open(private, service.clone(), None).await?);
    }
    images[0].write_at(0, &[0x22; 4096]).await?;
    images[1].write_at(4096, &[0x33; 4096]).await?;
    for image in &images {
        image.sync().await?;
    }
    let a = images[0].read_at(0, 8192).await?;
    let b = images[1].read_at(0, 8192).await?;
    ensure!(
        a[..4096] == [0x22; 4096] && a[4096..] == [0x11; 4096],
        "A private upper leaked or lost base"
    );
    ensure!(
        b[..4096] == [0x11; 4096] && b[4096..] == [0x33; 4096],
        "B private upper leaked or lost base"
    );
    ensure!(
        base.read_at(0, 8192).await?.as_ref() == [0x11; 8192],
        "immutable UB base changed"
    );
    ensure!(
        base.write_at(0, &[0; 512]).await.is_err(),
        "base unexpectedly writable"
    );
    let delta = output.join("child.commit");
    let descriptor = images[0]
        .create_snapshot_and_restack(&delta)
        .await?
        .context("missing child identity")?;
    images[0].write_at(4096, &[0x44; 4096]).await?;
    let replica = cfg.lowers[0].ub.clone().unwrap();
    let ancestor = output.join("durable-ancestor.commit");
    let ancestor_export = ancestor.clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(ancestor_export)?;
        overlaybd::backend::ub::copy_verified_stored_layer(&replica, &mut file)
    })
    .await??;
    // Reopen the child from durable files only: no UB hint is carried forward.
    let mut child = cfg.clone();
    child.lowers[0].ub = None;
    child.lowers[0].file = ancestor.to_string_lossy().into_owned();
    child.lowers.push(LayerConfig {
        file: delta.to_string_lossy().into_owned(),
        digest: descriptor.digest,
        size: descriptor.size,
        ..Default::default()
    });
    let child = ImageFile::open(child, service, None).await?;
    let child_bytes = child.read_at(0, 8192).await?;
    ensure!(
        child_bytes[..4096] == [0x22; 4096] && child_bytes[4096..] == [0x11; 4096],
        "durable child lost UB ancestor or included post-capture writes"
    );
    println!(
        "{}",
        json!({"status": "UB_LAYER_FORMAT_COW_PROBE_COMPLETED", "image": image,
        "output": output, "required_ub": true, "two_private_uppers": true,
        "base_unchanged": true, "durable_child_reopen_without_ub": true,
        "scope": "Real OverlayBD stored bytes and local uppers; no ublk/Guest execution claim"})
    );
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    match args.first().and_then(|a| a.to_str()) {
        Some("prepare") if args.len() == 2 => prepare(Path::new(&args[1])).await,
        Some("check") if args.len() == 4 => check(Path::new(&args[1]), Path::new(&args[2]), Path::new(&args[3])).await,
        _ => bail!("usage: ub_layer_probe prepare NEW_ABSOLUTE_DIR | check IMAGE_JSON REPLICA_INDEX NEW_ABSOLUTE_OUTPUT_DIR"),
    }
}
