// SPDX-License-Identifier: Apache-2.0
//! Portable pmem references and explicit, freshly verified FD rebindings.
//! The orchestrator owns content verification and leases; saved FDs are rejected.
use std::io;

use serde::Deserialize;

use super::native_fd::NativePmemFd;

pub const RESTORE_FILE: &str = "aenv-pmem-restore.json";
const PREFIX: &str = "aenv-pmem-content:";

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub fn saved_path(runtime: &str) -> io::Result<String> {
    match NativePmemFd::parse(runtime)? {
        Some(native) => native
            .snapshot_reference()
            .ok_or_else(|| invalid("native pmem snapshots require v3/v4 content identity")),
        None if runtime.starts_with(PREFIX) => {
            Err(invalid("unresolved content reference is not a live device"))
        }
        None => Ok(runtime.to_owned()),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Rebindings {
    version: u32,
    paths: Vec<String>,
}

/// Resolve from bounded metadata; content equality, complete length and unique
/// matching are mandatory. Missing mappings never fall back to old descriptors.
pub fn resolve(saved: &str, json: &[u8]) -> io::Result<String> {
    if !saved.starts_with(PREFIX) || saved.len() > 128 || json.len() > 65536 {
        return Err(invalid("invalid saved reference or oversized rebindings"));
    }
    let binding: Rebindings =
        serde_json::from_slice(json).map_err(|_| invalid("invalid pmem rebindings"))?;
    if binding.version != 1 || binding.paths.is_empty() || binding.paths.len() > 8 {
        return Err(invalid("invalid pmem rebinding version/count"));
    }
    let mut seen = std::collections::HashSet::new();
    let mut selected = None;
    for path in binding.paths {
        let native = NativePmemFd::parse(&path)?
            .ok_or_else(|| invalid("rebinding must be an explicit native descriptor"))?;
        let identity = native
            .snapshot_reference()
            .ok_or_else(|| invalid("rebinding lacks content identity"))?;
        if !seen.insert(identity.clone()) {
            return Err(invalid("duplicate pmem content rebinding"));
        }
        if identity == saved {
            selected = Some(path);
        }
    }
    selected.ok_or_else(|| invalid("no verified FD rebinding for saved pmem content"))
}

#[cfg(target_os = "linux")]
pub fn restored_path(saved: &str) -> io::Result<String> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    if super::native_fd::is_native_pmem_path(saved) {
        return Err(invalid("process-local native FD in snapshot refused"));
    }
    if !saved.starts_with(PREFIX) {
        return Ok(saved.to_owned());
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(RESTORE_FILE)?;
    let metadata = file.metadata()?;
    let directory = std::fs::metadata(".")?;
    if !metadata.is_file()
        || metadata.len() > 65536
        || metadata.nlink() != 1
        || !directory.is_dir()
        || directory.mode() & 0o077 != 0
        || metadata.uid() != directory.uid()
        || metadata.mode() & 0o077 != 0
    {
        return Err(invalid(
            "pmem rebinding file must belong to the private launch directory owner",
        ));
    }
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    resolve(saved, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn path(sha: char, fd: u32) -> String {
        format!(
            "aenv-pmem-fd:v3:{}:2097152:nc:{fd}@2097152",
            sha.to_string().repeat(64)
        )
    }
    #[test]
    fn fs_dax_restore_rebinds_content_without_persisting_node_fd_or_backend() {
        let digest = "a".repeat(64);
        let first = format!("aenv-pmem-fd:v4:{digest}:2097152:fsdax:10");
        let next = format!("aenv-pmem-fd:v4:{digest}:2097152:fsdax:11");
        let reference = saved_path(&first).unwrap();
        let table = serde_json::json!({"version": 1, "paths": [next.clone()]});
        assert_eq!(
            resolve(&reference, &serde_json::to_vec(&table).unwrap()).unwrap(),
            next
        );
        assert_eq!(reference, saved_path(&path('a', 64)).unwrap());
        let duplicate = serde_json::json!({"version": 1, "paths": [first, next]});
        assert!(resolve(&reference, &serde_json::to_vec(&duplicate).unwrap()).is_err());
    }
    #[test]
    fn saved_reference_omits_fd_and_restores_with_new_descriptor() {
        let reference = saved_path(&path('a', 64)).unwrap();
        assert_eq!(
            reference,
            format!("aenv-pmem-content:v1:{}:2097152", "a".repeat(64))
        );
        let new_path = path('a', 96);
        let table = serde_json::json!({"version":1,"paths":[new_path]});
        assert_eq!(
            resolve(&reference, &serde_json::to_vec(&table).unwrap()).unwrap(),
            new_path
        );
    }
    #[test]
    fn wrong_content_missing_duplicate_and_legacy_fds_are_rejected() {
        let reference = saved_path(&path('a', 64)).unwrap();
        for paths in [
            vec![],
            vec![path('b', 64)],
            vec![path('a', 64), path('a', 96)],
            vec!["aenv-pmem-fd:v2:2097152:nc:64@2097152".into()],
        ] {
            let table = serde_json::json!({"version":1,"paths":paths});
            assert!(resolve(&reference, &serde_json::to_vec(&table).unwrap()).is_err());
        }
        assert!(saved_path("aenv-pmem-fd:v1:10:2097152:nc").is_err());
        assert!(saved_path(&reference).is_err());
    }
    #[test]
    fn ordinary_file_snapshot_path_is_unchanged() {
        assert_eq!(saved_path("base.ext4").unwrap(), "base.ext4");
    }
    #[test]
    fn host_file_snapshot_rebinds_content_without_host_path_or_old_fd() {
        let digest = "a".repeat(64);
        let first = format!("aenv-pmem-fd:v5:{digest}:2097152:hostfile:10");
        let next = format!("aenv-pmem-fd:v5:{digest}:2097152:hostfile:11");
        let saved = saved_path(&first).unwrap();
        assert_eq!(saved, saved_path(&path('a', 64)).unwrap());
        let table = serde_json::json!({"version":1,"paths":[next.clone()]});
        assert_eq!(
            resolve(&saved, &serde_json::to_vec(&table).unwrap()).unwrap(),
            next
        );
        let table =
            serde_json::json!({"version":1,"paths":[next.replace(&digest,&"b".repeat(64))]});
        assert!(resolve(&saved, &serde_json::to_vec(&table).unwrap()).is_err());
    }
}
