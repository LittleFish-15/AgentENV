//! Owned 8MiB fixture: warm whole file, then observe only 3 accessed pages.
//! No Guest, SDK, service, device or global cache operation.
use anyhow::{bail, ensure, Context, Result};
use overlaybd::backend::local::LocalFile;
use overlaybd::virtual_file::{IoCtx, VirtualFile};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use storage_util::io_ring::{AsyncIoRingBuilder, URING};

fn main() -> Result<()> {
    let dir = PathBuf::from(
        std::env::args()
            .nth(1)
            .context("fixture directory required")?,
    );
    ensure!(
        dir.is_absolute() && dir.canonicalize()? == dir,
        "canonical fixture directory required"
    );
    let meta = dir.metadata()?;
    ensure!(
        meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o077 == 0,
        "private owned fixture required"
    );
    ensure!(
        unsafe { libc::sysconf(libc::_SC_PAGESIZE) } == 4096,
        "4KiB host pages required"
    );
    let path = dir.join("warm-fixture.bin");
    let mut writer = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    writer.write_all(&vec![0x5a; 8 * 1024 * 1024])?;
    writer.sync_all()?;
    drop(writer);
    let meta = path.metadata()?;
    let output = dir.join("trace.jsonl");
    let spec = std::env::current_exe()?.with_extension("access-spec");
    let mut cfg = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&spec)?;
    writeln!(
        cfg,
        "output={}\nmax_bytes=1048576\nmax_records=100\nallow={}:{}:{}",
        output.display(),
        meta.dev(),
        meta.ino(),
        meta.len()
    )?;
    drop(cfg);
    let first = dir.join("reader1/overlaybd/image.json");
    let second = dir.join("reader2/overlaybd/image.json");
    let file = LocalFile::open_ro(&path)?;
    let ring = AsyncIoRingBuilder::new().build()?;
    ensure!(
        URING.with(|slot| slot.set(ring.clone())).is_ok(),
        "uring slot already initialized"
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .on_thread_park(|| {
            URING.with(|slot| {
                slot.get()
                    .unwrap()
                    .borrow()
                    .submit()
                    .expect("submit own calibration reads");
            });
        })
        .build()?;
    let begin = overlaybd::rootfs_access_trace::now_ns();
    tokio::task::LocalSet::new().block_on(&runtime, async {
        let work = async {
            let a = file.read_at_with_ctx(IoCtx::new(&ring).with_read_source(&first), 0, 8192).await?;
            ensure!(a.len() == 8192 && a.iter().all(|b| *b == 0x5a), "first read differs");
            let mut b = vec![0u8; 8192];
            ensure!(file.read_at_into_with_ctx(IoCtx::new(&ring).with_read_source(&second), 4096, &mut b).await? == 8192, "second short read");
            ensure!(b.iter().all(|v| *v == 0x5a), "second read differs");
            // Repeat a warm buffered read; it must still produce attribution.
            let again = file.read_at_with_ctx(IoCtx::new(&ring).with_read_source(&first), 0, 8192).await?;
            ensure!(again == a, "repeat read differs");
            Ok::<(), anyhow::Error>(())
        };
        tokio::select! {
            result = tokio::time::timeout(std::time::Duration::from_secs(15), work) => result.context("calibration timed out")?,
            result = ring.handle_completion() => { bail!("completion loop exited: {result:?}") }
        }
    })?;
    let end = overlaybd::rootfs_access_trace::now_ns();
    std::thread::sleep(std::time::Duration::from_secs(2));
    let evidence = serde_json::json!({"fixture":path,"file_bytes":meta.len(),"dev":meta.dev(),"inode":meta.ino(),
        "source1":first,"source2":second,"start_ns":begin,"end_ns":end,"trace":output,
        "whole_fixture_warmed":true,"guest_created":false,"service_changed":false});
    let result_path = dir.join("calibration-input.json");
    let mut result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&result_path)?;
    result.write_all(serde_json::to_string_pretty(&evidence)?.as_bytes())?;
    std::fs::set_permissions(&spec, std::fs::Permissions::from_mode(0o600))?;
    println!("CALIBRATION_IO_COMPLETED");
    Ok(())
}
