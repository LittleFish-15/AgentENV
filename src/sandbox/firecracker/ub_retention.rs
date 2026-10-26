//! Preserve diagnostic inputs when a required UB rootfs was not stopped.
//! This records uncertainty; it is not a resource-recovery or retirement API.
#[cfg(unix)]
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde_json::Value;
use tempfile::TempDir;

pub(super) fn preserve_unresolved_rootfs(dir: &mut TempDir, identity: Value) -> Result<PathBuf> {
    // Disable deletion before any fallible reporting. A full disk or existing
    // marker must not cause the still-needed image/upper directory to vanish.
    dir.disable_cleanup(true);
    let path = dir.path().join("ub-rootfs-unresolved.json");
    let record = serde_json::json!({
        "version": 1,
        "state": "unresolved_preserved",
        "identity": identity,
        "temporaryDirectoryCleanupDisabled": true,
        "fcExitConfirmed": false,
        "rootfsDeviceExitConfirmed": false,
        "sdkRetirementAuthorized": false,
        "readPermitsMayCloseOnProcessExit": true,
        "scope": "diagnostic identity hints; independently reconcile before cleanup"
    });
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options
        .open(&path)
        .context("create unresolved UB marker without replacing prior evidence")?;
    serde_json::to_writer(&mut output, &record).context("write unresolved UB marker")?;
    output.write_all(b"\n")?;
    output.sync_all().context("sync unresolved UB marker")?;
    #[cfg(unix)]
    File::open(dir.path())?
        .sync_all()
        .context("sync unresolved UB directory")?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unresolved_directory_and_marker_survive_drop() {
        let parent = tempfile::tempdir().unwrap();
        let mut work = tempfile::tempdir_in(parent.path()).unwrap();
        let path = work.path().to_path_buf();
        std::fs::write(path.join("image.json"), b"retained config").unwrap();
        let marker =
            preserve_unresolved_rootfs(&mut work, serde_json::json!({"sandboxId":"test"})).unwrap();
        drop(work);
        assert_eq!(
            std::fs::read(path.join("image.json")).unwrap(),
            b"retained config"
        );
        let value: Value = serde_json::from_slice(&std::fs::read(marker).unwrap()).unwrap();
        assert_eq!(value["state"], "unresolved_preserved");
        assert_eq!(value["sdkRetirementAuthorized"], false);
        assert_eq!(value["readPermitsMayCloseOnProcessExit"], true);
    }

    #[test]
    fn existing_marker_is_not_overwritten_and_directory_still_survives() {
        let parent = tempfile::tempdir().unwrap();
        let mut work = tempfile::tempdir_in(parent.path()).unwrap();
        let path = work.path().to_path_buf();
        let marker = path.join("ub-rootfs-unresolved.json");
        std::fs::write(&marker, b"previous evidence").unwrap();
        assert!(preserve_unresolved_rootfs(&mut work, Value::Null).is_err());
        drop(work);
        assert_eq!(std::fs::read(marker).unwrap(), b"previous evidence");
    }

    #[test]
    fn ordinary_temp_directory_still_cleans_up() {
        let parent = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir_in(parent.path()).unwrap();
        let path = work.path().to_path_buf();
        drop(work);
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn unix_marker_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let parent = tempfile::tempdir().unwrap();
        let mut work = tempfile::tempdir_in(parent.path()).unwrap();
        let marker = preserve_unresolved_rootfs(&mut work, Value::Null).unwrap();
        assert_eq!(
            std::fs::metadata(marker).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
