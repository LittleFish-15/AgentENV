//! Optional diagnostic observer for successful, context-attributed local reads.
//! No payload bytes are logged. This does not change read results or caching.
use std::path::Path;

pub fn quote(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 32 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn rootfs_source(source: &Path) -> bool {
    source.is_absolute() && source.ends_with("overlaybd/image.json")
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{quote, rootfs_source};
    use std::collections::HashSet;
    use std::ffi::c_long;
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex, OnceLock};
    use std::time::Duration;

    #[repr(C)]
    struct Timespec {
        sec: c_long,
        nsec: c_long,
    }
    unsafe extern "C" {
        fn geteuid() -> u32;
        fn clock_gettime(clock: i32, tp: *mut Timespec) -> i32;
    }
    pub fn now_ns() -> u64 {
        let mut t = Timespec { sec: 0, nsec: 0 };
        // CLOCK_MONOTONIC: shared with Python time.monotonic_ns on this node.
        if unsafe { clock_gettime(1, &mut t) } != 0 || t.sec < 0 || t.nsec < 0 {
            return 0;
        }
        (t.sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(t.nsec as u64)
    }

    struct State {
        file: File,
        sequence: u64,
        bytes: u64,
        dropped: u64,
        errors: u64,
        unsupported: u64,
        direct_reads: u64,
    }
    struct Sink {
        state: Mutex<State>,
        allowed: HashSet<(u64, u64, u64)>,
        status: PathBuf,
        max_bytes: u64,
        max_records: u64,
    }
    static TRACE: OnceLock<Option<Arc<Sink>>> = OnceLock::new();

    fn owned_regular(path: &Path, maximum: u64) -> std::io::Result<File> {
        let uid = unsafe { geteuid() };
        let entry = std::fs::symlink_metadata(path)?;
        if !entry.is_file()
            || entry.uid() != uid
            || entry.mode() & 0o022 != 0
            || entry.len() > maximum
        {
            return Err(std::io::Error::other("unexpected observer file"));
        }
        let file = File::open(path)?;
        let actual = file.metadata()?;
        if actual.dev() != entry.dev() || actual.ino() != entry.ino() || actual.len() > maximum {
            return Err(std::io::Error::other("observer file identity changed"));
        }
        Ok(file)
    }

    fn initialize() -> std::io::Result<Arc<Sink>> {
        let config = std::env::current_exe()?.with_extension("access-spec");
        let mut text = String::new();
        owned_regular(&config, 65536)?
            .take(65537)
            .read_to_string(&mut text)?;
        if text.len() > 65536 {
            return Err(std::io::Error::other("observer spec oversized"));
        }
        let mut output = None;
        let mut allowed = HashSet::new();
        let mut max_bytes = 0;
        let mut max_records = 0;
        for line in text.lines() {
            if let Some(value) = line.strip_prefix("output=") {
                output = Some(PathBuf::from(value));
            } else if let Some(value) = line.strip_prefix("max_bytes=") {
                max_bytes = value.parse().unwrap_or(0);
            } else if let Some(value) = line.strip_prefix("max_records=") {
                max_records = value.parse().unwrap_or(0);
            } else if let Some(value) = line.strip_prefix("allow=") {
                let parts: Vec<_> = value.split(':').map(str::parse::<u64>).collect();
                if parts.len() != 3 || parts.iter().any(Result::is_err) {
                    return Err(std::io::Error::other("invalid allowed inode"));
                }
                allowed.insert((
                    parts[0].as_ref().copied().unwrap(),
                    parts[1].as_ref().copied().unwrap(),
                    parts[2].as_ref().copied().unwrap(),
                ));
            } else {
                return Err(std::io::Error::other("unknown observer setting"));
            }
        }
        let output = output.ok_or_else(|| std::io::Error::other("no observer output"))?;
        if !output.is_absolute()
            || allowed.is_empty()
            || allowed.len() > 256
            || !(1048576..=268435456).contains(&max_bytes)
            || !(1..=1000000).contains(&max_records)
        {
            return Err(std::io::Error::other("observer bounds invalid"));
        }
        let parent = output
            .parent()
            .ok_or_else(|| std::io::Error::other("output has no parent"))?;
        let meta = std::fs::symlink_metadata(parent)?;
        if !meta.is_dir()
            || meta.uid() != unsafe { geteuid() }
            || meta.mode() & 0o077 != 0
            || parent.canonicalize()? != parent
        {
            return Err(std::io::Error::other(
                "observer output must use a private owned directory",
            ));
        }
        let status = output.with_extension("status.json");
        if status.exists() || status.with_extension("tmp").exists() {
            return Err(std::io::Error::other("observer status already exists"));
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&output)?;
        let build_patch = option_env!("AENV_OBSERVER_BUILD_PATCH_SHA").unwrap_or("unattested");
        let header=format!("{{\"kind\":\"header\",\"version\":1,\"build_patch_sha256\":{},\"pid\":{},\"uid\":{},\"clock\":\"CLOCK_MONOTONIC\",\"mono_ns\":{},\"allowed_files\":{}}}\n",quote(build_patch),std::process::id(),unsafe{geteuid()},now_ns(),allowed.len());
        file.write_all(header.as_bytes())?;
        let sink = Arc::new(Sink {
            state: Mutex::new(State {
                file,
                sequence: 0,
                bytes: header.len() as u64,
                dropped: 0,
                errors: 0,
                unsupported: 0,
                direct_reads: 0,
            }),
            allowed,
            status,
            max_bytes,
            max_records,
        });
        let heartbeat = Arc::clone(&sink);
        std::thread::Builder::new()
            .name("access-observer".into())
            .spawn(move || loop {
                let _ = heartbeat.publish_status();
                std::thread::sleep(Duration::from_secs(1));
            })?;
        Ok(sink)
    }
    fn sink() -> Option<&'static Arc<Sink>> {
        TRACE
            .get_or_init(|| match initialize() {
                Ok(s) => Some(s),
                Err(e) => {
                    eprintln!("ROOTFS_ACCESS_OBSERVER_DISABLED: {e}");
                    None
                }
            })
            .as_ref()
    }
    impl Sink {
        fn publish_status(&self) -> std::io::Result<()> {
            let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
            let value=format!("{{\"version\":1,\"pid\":{},\"mono_ns\":{},\"records_written\":{},\"bytes_written\":{},\"dropped_records\":{},\"errors\":{},\"unsupported_context_calls\":{},\"direct_reads\":{}}}\n",std::process::id(),now_ns(),s.sequence,s.bytes,s.dropped,s.errors,s.unsupported,s.direct_reads);
            let temporary = self.status.with_extension("tmp");
            let result = (|| {
                let mut f = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&temporary)?;
                f.write_all(value.as_bytes())?;
                drop(f);
                std::fs::rename(&temporary, &self.status)
            })();
            if result.is_err() {
                s.errors += 1;
            }
            result
        }
    }
    pub fn fallback(source: &Path) {
        if !rootfs_source(source) {
            return;
        }
        if let Some(sink) = sink() {
            sink.state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .unsupported += 1;
        }
    }
    pub fn record(
        source: &Path,
        file: &File,
        path: &Path,
        offset: u64,
        length: usize,
        direct: bool,
        start: u64,
    ) {
        if length == 0 || !rootfs_source(source) {
            return;
        }
        let Some(sink) = sink() else {
            return;
        };
        record_into(sink, source, file, path, (offset, length), direct, start);
    }
    fn record_into(
        sink: &Sink,
        source: &Path,
        file: &File,
        path: &Path,
        range: (u64, usize),
        direct: bool,
        start: u64,
    ) {
        let (offset, length) = range;
        if length == 0 || !rootfs_source(source) {
            return;
        }
        let meta = match file.metadata() {
            Ok(v) => v,
            Err(_) => {
                sink.state.lock().unwrap_or_else(|p| p.into_inner()).errors += 1;
                return;
            }
        };
        if !meta.is_file() || meta.uid() != unsafe { geteuid() } {
            sink.state.lock().unwrap_or_else(|p| p.into_inner()).errors += 1;
            return;
        }
        // Keep unmatched local reads visible as metadata, so a missing lower
        // whitelist binding cannot silently turn into a false zero result.
        let allowed_lower = sink.allowed.contains(&(meta.dev(), meta.ino(), meta.len()));
        let end = now_ns();
        let mut s = sink.state.lock().unwrap_or_else(|p| p.into_inner());
        if start == 0
            || end < start
            || offset
                .checked_add(length as u64)
                .is_none_or(|v| v > meta.len())
        {
            s.errors += 1;
            return;
        }
        if direct {
            s.direct_reads += 1;
        }
        let row=format!("{{\"kind\":\"read\",\"seq\":{},\"source\":{},\"path\":{},\"dev\":{},\"inode\":{},\"file_bytes\":{},\"offset\":{},\"bytes\":{},\"direct_io\":{},\"allowed_lower\":{},\"start_ns\":{},\"end_ns\":{}}}\n",s.sequence,quote(&source.to_string_lossy()),quote(&path.to_string_lossy()),meta.dev(),meta.ino(),meta.len(),offset,length,direct,allowed_lower,start,end);
        if s.sequence >= sink.max_records || s.bytes + row.len() as u64 > sink.max_bytes {
            s.dropped += 1;
            return;
        }
        match s.file.write_all(row.as_bytes()) {
            Ok(()) => {
                s.sequence += 1;
                s.bytes += row.len() as u64;
            }
            Err(_) => s.errors += 1,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        fn fixture() -> (tempfile::TempDir, File, PathBuf, Sink) {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("lower");
            std::fs::write(&path, b"secret_payload_never_logged").unwrap();
            let file = File::open(&path).unwrap();
            let m = file.metadata().unwrap();
            let sink = Sink {
                state: Mutex::new(State {
                    file: File::create(dir.path().join("trace")).unwrap(),
                    sequence: 0,
                    bytes: 0,
                    dropped: 0,
                    errors: 0,
                    unsupported: 0,
                    direct_reads: 0,
                }),
                allowed: HashSet::from([(m.dev(), m.ino(), m.len())]),
                status: dir.path().join("status.json"),
                max_bytes: 1048576,
                max_records: 100,
            };
            (dir, file, path, sink)
        }
        #[test]
        fn records_ranges_and_sources_without_payload() {
            let (dir, file, path, sink) = fixture();
            record_into(
                &sink,
                Path::new("/one/overlaybd/image.json"),
                &file,
                &path,
                (0, 4),
                false,
                now_ns(),
            );
            record_into(
                &sink,
                Path::new("/two/overlaybd/image.json"),
                &file,
                &path,
                (2, 6),
                false,
                now_ns(),
            );
            let data = std::fs::read_to_string(dir.path().join("trace")).unwrap();
            assert!(!data.contains("secret_payload_never_logged"));
            let rows: Vec<serde_json::Value> = data
                .lines()
                .map(|s| serde_json::from_str(s).unwrap())
                .collect();
            assert_eq!(rows.len(), 2);
            assert_eq!(rows[0]["seq"], 0);
            assert_eq!(rows[1]["seq"], 1);
            assert_eq!(rows[1]["offset"], 2);
            assert_eq!(rows[1]["bytes"], 6);
            assert_ne!(rows[0]["source"], rows[1]["source"]);
            sink.publish_status().unwrap();
            let state: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&sink.status).unwrap()).unwrap();
            assert_eq!(state["records_written"], 2);
            assert_eq!(state["errors"], 0);
        }
        #[test]
        fn bounds_and_nonrootfs_are_not_silent_success() {
            let (_dir, file, path, mut sink) = fixture();
            sink.max_records = 1;
            record_into(
                &sink,
                Path::new("/one/memory/image.json"),
                &file,
                &path,
                (0, 4),
                false,
                now_ns(),
            );
            assert_eq!(sink.state.lock().unwrap().sequence, 0);
            record_into(
                &sink,
                Path::new("/one/overlaybd/image.json"),
                &file,
                &path,
                (0, 4),
                false,
                now_ns(),
            );
            record_into(
                &sink,
                Path::new("/one/overlaybd/image.json"),
                &file,
                &path,
                (0, 4),
                true,
                now_ns(),
            );
            assert_eq!(sink.state.lock().unwrap().dropped, 1);
            record_into(
                &sink,
                Path::new("/one/overlaybd/image.json"),
                &file,
                &path,
                (u64::MAX, 4),
                false,
                now_ns(),
            );
            assert_eq!(sink.state.lock().unwrap().errors, 1);
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::{fallback, now_ns, record};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quote_control_characters() {
        assert_eq!(quote("a\n\"\\\t\u{1}"), "\"a\\n\\\"\\\\\\t\\u0001\"");
    }
    #[test]
    fn quote_unicode() {
        assert_eq!(quote("层"), "\"层\"");
    }
    #[test]
    fn scope_matches_rootfs_component_suffix() {
        let owned = if cfg!(windows) {
            "C:/owned/run/overlaybd/image.json"
        } else {
            "/owned/run/overlaybd/image.json"
        };
        assert!(rootfs_source(Path::new(owned)));
        assert!(!rootfs_source(Path::new("/owned/memory/image.json")));
        assert!(!rootfs_source(Path::new("overlaybd/image.json")));
    }
}
