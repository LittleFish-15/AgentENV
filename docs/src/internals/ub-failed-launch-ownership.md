# Failed launch ownership and retry

The orchestrator must not treat an unsuccessful `stop()` as proof that a
Firecracker process, private ublk device, or UB read session has been released.
This applies both when `start_nowait()` itself fails and when readiness or
metadata publication fails after the backend was registered.

`cleanup_failed_launch` now stops before detaching the runtime. On a stop
failure, `retain_failed_launch` keeps the backend handle, removes that
incarnation's proxy route and records `Killing` plus deletion progress `Stop`.
An explicit delete retry calls backend stop again. It does not capture or
publish volumes from a failed launch. Only confirmed stop permits subsequent
volume cleanup, metadata removal and starting-image protection release.
A failed resume is not rolled back to a resumable `Paused` state while its
new runtime may still be alive.

If the metadata store cannot record this state, or a different backend handle
already owns the same sandbox ID, the old handle is retained separately. The
replacement handle and route are not overwritten. Deletion of that ID is
blocked for reconciliation; an empty metadata inventory does not authorize
release. Image maintenance includes the retained handles and unions artifact
paths for identical IDs. Shutdown reports failure while unresolved identities
remain; it must not report success based only on an empty store. Ordinary
retained `Killing` launches use the existing bounded shutdown cleanup passes.

This is **in-process ownership preservation**, not durable recovery of kernel
resources after Runtime termination, power loss, or a crash. The quarantine
does not implement an automatic takeover/reconciliation API. Operators must
retain controller journals and independently establish process/device/session
identity before any SDK retirement or service restart. Returning a shutdown
error cannot guarantee the enclosing service manager keeps the process alive.
No hardware lifecycle success is inferred from unit tests or compilation.

The regression tests under `orchestrator::tests::ub_failed_launch_` cover
start/readiness plus stop failure, failed resume, metadata failure, stale
identity preservation and bounded shutdown retry. Run these on the native
Linux build together with the existing normal launch/rollback/delete tests.
The preserved full deployment and its binary/configuration snapshots are not
updated merely by adding this source candidate.

If a `FirecrackerSandbox` is ultimately dropped while required UB Runtime
permits are still present, its temporary work directory now disables automatic
deletion before attempting a private `ub-rootfs-unresolved.json` marker. The
marker records the sandbox ID, PID hint, image/device paths and exact bound UB
object generations. It uses exclusive creation (and owner-only permissions on
Unix), syncs the file and directory, and never overwrites earlier evidence.
A marker-write failure still leaves temporary-directory cleanup disabled.
Confirmed normal stop removes the UB permits, so normal directory cleanup
remains enabled. This condition does not alter native-pmem or memfile cleanup.

The marker does not attest PID/startTicks stability, current process/device
liveness or SDK retirement safety. It explicitly permits no SDK retirement and
states that process exit may close the read permits. Runtime termination,
external deletion and power-loss recovery still require independent
reconciliation; preserving these files alone is not durable kernel ownership.
