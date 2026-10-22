//! Durable native-pmem source files. These are disk artifacts, never Guest RAM.
use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

const BUFFER_BYTES: usize = 1024 * 1024;

#[derive(Default)]
pub(crate) struct CaptureCancellation(std::sync::Arc<AtomicBool>);

impl CaptureCancellation {
    pub(crate) fn flag(&self) -> std::sync::Arc<AtomicBool> {
        self.0.clone()
    }
}

impl Drop for CaptureCancellation {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

pub(crate) fn relative_name(index: usize, sha256: &str) -> Result<PathBuf> {
    let hash = sha256.strip_prefix("sha256:").unwrap_or("");
    ensure!(
        index < 8
            && hash.len() == 64
            && hash
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "invalid native archive identity"
    );
    Ok(PathBuf::from("native-pmem").join(format!("{index:02}-{hash}.img")))
}

fn source_file(path: &Path, bytes: u64) -> Result<File> {
    ensure!(
        path.is_absolute() && bytes > 0 && bytes.is_multiple_of(2 * 1024 * 1024),
        "native archive source must be absolute and 2MiB aligned"
    );
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .context("open immutable native archive source")?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() == bytes,
        "native archive source type or length differs"
    );
    Ok(file)
}

#[derive(Debug)]
struct Source {
    file: File,
    sha256: String,
    bytes: u64,
}

/// Open file descriptions survive unlink/cache eviction. Shared captures use
/// positional reads, never a shared seek cursor. Runtime configs clone an Arc.
#[derive(Debug)]
pub(crate) struct RetainedSources {
    sources: Vec<Source>,
}

impl RetainedSources {
    pub(crate) fn open(paths: &[PathBuf], identities: &[(String, u64)]) -> Result<Self> {
        ensure!(
            !paths.is_empty() && paths.len() <= 8 && paths.len() == identities.len(),
            "native snapshot sources must cover every pmem layer"
        );
        let mut sources = Vec::new();
        for (index, (path, (sha256, bytes))) in paths.iter().zip(identities).enumerate() {
            relative_name(index, sha256)?;
            sources.push(Source {
                file: source_file(path, *bytes)?,
                sha256: sha256.clone(),
                bytes: *bytes,
            });
        }
        Ok(Self { sources })
    }

    #[cfg(test)]
    pub(crate) fn archive_into(&self, snapshot_root: &Path) -> Result<Vec<PathBuf>> {
        self.archive_into_cancellable(snapshot_root, &AtomicBool::new(false))
    }

    pub(crate) fn archive_into_cancellable(
        &self,
        snapshot_root: &Path,
        cancelled: &AtomicBool,
    ) -> Result<Vec<PathBuf>> {
        ensure!(
            !cancelled.load(Ordering::Acquire),
            "native archive cancelled"
        );
        let directory = snapshot_root.join("native-pmem");
        std::fs::create_dir(&directory).context("create new snapshot native archive directory")?;
        let mut paths = Vec::new();
        for (index, source) in self.sources.iter().enumerate() {
            let target = snapshot_root.join(relative_name(index, &source.sha256)?);
            copy_verified(
                &source.file,
                &target,
                &source.sha256,
                source.bytes,
                Some(cancelled),
            )?;
            paths.push(target);
        }
        #[cfg(unix)]
        File::open(&directory)?.sync_all()?;
        Ok(paths)
    }
}

fn read_at(file: &File, data: &mut [u8], offset: u64) -> std::io::Result<usize> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.read_at(data, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        file.seek_read(data, offset)
    }
}

#[cfg(unix)]
fn stamp(meta: &std::fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    use std::os::unix::fs::MetadataExt;
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

#[cfg(windows)]
fn stamp(
    meta: &std::fs::Metadata,
) -> (
    u64,
    Option<std::time::SystemTime>,
    Option<std::time::SystemTime>,
) {
    (meta.len(), meta.modified().ok(), meta.created().ok())
}

fn copy_verified(
    source: &File,
    destination: &Path,
    expected: &str,
    bytes: u64,
    cancelled: Option<&AtomicBool>,
) -> Result<()> {
    let before = source.metadata()?;
    ensure!(
        before.is_file() && before.len() == bytes,
        "native archive source changed"
    );
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut output = options
        .open(destination)
        .context("create new native snapshot archive")?;
    let mut hash = Sha256::new();
    let mut offset = 0;
    let mut buffer = vec![0; BUFFER_BYTES];
    while offset < bytes {
        ensure!(
            !cancelled.is_some_and(|flag| flag.load(Ordering::Acquire)),
            "native archive cancelled"
        );
        let count = (bytes - offset).min(buffer.len() as u64) as usize;
        let mut filled = 0;
        while filled < count {
            let got = read_at(source, &mut buffer[filled..count], offset + filled as u64)?;
            ensure!(got != 0, "short native archive source");
            filled += got;
        }
        hash.update(&buffer[..count]);
        ensure!(
            !cancelled.is_some_and(|flag| flag.load(Ordering::Acquire)),
            "native archive cancelled"
        );
        if buffer[..count].iter().all(|byte| *byte == 0) {
            output.seek(SeekFrom::Current(count as i64))?;
        } else {
            output.write_all(&buffer[..count])?;
        }
        offset += count as u64;
    }
    ensure!(
        stamp(&before) == stamp(&source.metadata()?),
        "native source changed during archive"
    );
    ensure!(
        format!("sha256:{:x}", hash.finalize()) == expected,
        "native archive content differs"
    );
    output.set_len(bytes)?;
    output.sync_all()?;
    Ok(())
}

pub(crate) fn copy_path(
    source: &Path,
    destination: &Path,
    expected: &str,
    bytes: u64,
) -> Result<()> {
    let input = source_file(source, bytes)?;
    copy_verified(&input, destination, expected, bytes, None)
}

pub(crate) fn verify_path(path: &Path, expected: &str, bytes: u64) -> Result<()> {
    let mut file = source_file(path, bytes)?;
    let before = file.metadata()?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0; BUFFER_BYTES];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    ensure!(
        stamp(&before) == stamp(&file.metadata()?),
        "native artifact changed during validation"
    );
    ensure!(
        format!("sha256:{:x}", hash.finalize()) == expected,
        "native artifact digest differs"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (tempfile::TempDir, PathBuf, String, u64) {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("base.img");
        let mut bytes = vec![0; 2 * 1024 * 1024];
        bytes[4096] = 73;
        std::fs::write(&path, &bytes).unwrap();
        (
            root,
            path,
            format!("sha256:{:x}", Sha256::digest(&bytes)),
            bytes.len() as u64,
        )
    }
    #[test]
    fn complete_sparse_archive_is_verified_and_existing_destination_is_preserved() {
        let (root, source, hash, bytes) = fixture();
        let target = root.path().join("copy.img");
        copy_path(&source, &target, &hash, bytes).unwrap();
        verify_path(&target, &hash, bytes).unwrap();
        assert!(copy_path(&source, &target, &hash, bytes).is_err());
        assert!(verify_path(&target, &format!("sha256:{}", "f".repeat(64)), bytes).is_err());
    }
    #[test]
    fn concurrent_captures_have_independent_offsets_and_matching_content() {
        let (root, source, hash, bytes) = fixture();
        let retained = std::sync::Arc::new(
            RetainedSources::open(&[source], &[(hash.clone(), bytes)]).unwrap(),
        );
        let mut children = Vec::new();
        for index in 0..2 {
            let target = root.path().join(format!("snapshot-{index}"));
            std::fs::create_dir(&target).unwrap();
            let retained = retained.clone();
            children.push(std::thread::spawn(move || {
                retained.archive_into(&target).unwrap()
            }));
        }
        for child in children {
            verify_path(&child.join().unwrap()[0], &hash, bytes).unwrap();
        }
    }
    #[test]
    fn changed_source_is_rejected_and_partial_is_not_declared_valid() {
        let (root, source, hash, bytes) = fixture();
        let retained =
            RetainedSources::open(std::slice::from_ref(&source), &[(hash, bytes)]).unwrap();
        OpenOptions::new()
            .write(true)
            .open(source)
            .unwrap()
            .write_all(b"changed")
            .unwrap();
        let snapshot = root.path().join("snapshot");
        std::fs::create_dir(&snapshot).unwrap();
        assert!(retained.archive_into(&snapshot).is_err());
    }
    #[test]
    fn artifact_names_never_accept_paths_or_unknown_layers() {
        assert!(relative_name(0, "../../other").is_err());
        assert!(relative_name(8, &format!("sha256:{}", "a".repeat(64))).is_err());
    }
    #[test]
    fn retained_descriptor_survives_source_path_removal() {
        let (root, source, hash, bytes) = fixture();
        let retained =
            RetainedSources::open(std::slice::from_ref(&source), &[(hash.clone(), bytes)]).unwrap();
        std::fs::remove_file(source).unwrap();
        let snapshot = root.path().join("after-unlink");
        std::fs::create_dir(&snapshot).unwrap();
        let paths = retained.archive_into(&snapshot).unwrap();
        verify_path(&paths[0], &hash, bytes).unwrap();
    }
    #[test]
    fn cancelled_capture_does_not_create_a_new_archive_directory() {
        let (root, source, hash, bytes) = fixture();
        let retained = RetainedSources::open(&[source], &[(hash, bytes)]).unwrap();
        let snapshot = root.path().join("cancelled");
        std::fs::create_dir(&snapshot).unwrap();
        assert!(retained
            .archive_into_cancellable(&snapshot, &AtomicBool::new(true))
            .is_err());
        assert!(!snapshot.join("native-pmem").exists());
    }
    #[test]
    fn dropped_async_owner_signals_the_retained_worker_flag() {
        let owner = CaptureCancellation::default();
        let worker = owner.flag();
        assert!(!worker.load(Ordering::Acquire));
        drop(owner);
        assert!(worker.load(Ordering::Acquire));
    }
}
