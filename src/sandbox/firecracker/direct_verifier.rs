//! Keep device faults in an unprivileged child and retain leases through exit.
use super::direct_backing::{BackingSpec, DeviceRuntime, PinnedBacking};
use crate::privileges::{spawn_scoped, ScopedSpawnSpec};
use anyhow::{ensure, Context, Result};
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use tokio::time::{timeout, Duration};

pub async fn verify(
    backing: PinnedBacking,
    spec: BackingSpec,
    runtime: DeviceRuntime,
) -> Result<PinnedBacking> {
    let deadline = runtime.verification_timeout_secs;
    // Dropping the caller's JoinHandle detaches this supervisor; it does not
    // cancel verification and drop its lease. The child also inherits a lease.
    let job = tokio::spawn(async move {
        let mut child = spawn_scoped(ScopedSpawnSpec {
            argv: vec![
                CString::new(runtime.verifier.as_os_str().as_bytes())?,
                CString::new(backing.verification_path().as_os_str().as_bytes())?,
                CString::new(
                    spec.sha256
                        .strip_prefix("sha256:")
                        .context("missing digest prefix")?,
                )?,
            ],
            cwd: None,
            stdout: None,
            stderr: None,
            process_group: false,
            netns: None,
            fd_handoff: None,
            backing_handoffs: backing.verification_handoffs(),
            capabilities: &[],
        })
        .await
        .context("spawn isolated NC device verifier")?;
        let status = match timeout(Duration::from_secs(deadline), child.wait()).await {
            Ok(Ok(status)) => status,
            result => {
                let _ = child.start_kill();
                // If the kernel cannot reap it promptly, the inherited socket
                // keeps the provider lease alive after this supervisor returns.
                let reaped = timeout(Duration::from_secs(5), child.wait()).await;
                anyhow::bail!(
                    "native device verifier incomplete: {result:?}; termination/reap: {reaped:?}"
                );
            }
        };
        ensure!(
            status.success(),
            "native device content verifier failed: {status}"
        );
        Ok::<_, anyhow::Error>(backing)
    });
    timeout(Duration::from_secs(deadline + 10), job)
        .await
        .context("native verifier supervisor exceeded its deadline; child lease remains pinned")??
}
