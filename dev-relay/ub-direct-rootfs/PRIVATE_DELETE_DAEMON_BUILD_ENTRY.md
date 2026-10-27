# Native daemon-only fix for private rootfs deletion

Fixed core: `d97d2388e6985e7d28faa3746b91fe54c18aaf60` on `fix/ub-rootfs-private-delete`.
Entry: `A_build_private_delete_daemon_v1.py`, 243866 bytes, SHA256 `7c280363779db70b8fa9b2a4aa45fd849830797ca7de933b3352ce9d144448c1`.

Run on A as ordinary jwk (UID1204/GID1205, zero capabilities), outside measurement
windows. Default is PLAN; --run executes four daemon private-registry tests and
builds only uvm-ublk-daemon. This fixes Delete looking only in the managed table
when a runtime rootfs was actually registered as active-exclusive. Shared and
idle pool devices remain outside Delete. Missing private devices remain errors.

The source is the preserved full version plus exactly server.rs and its lifecycle
documentation; it does not pull in the separate overnight Runtime or demand
candidates. Old source and captured/deployed server/daemon artifacts are checked
before and after. The previously successful Cargo dependency target is reused
under Cargo's normal lock. Its cache outputs may be regenerated; the immutable
captured/deployed full binaries are not that cache. The new linked daemon is
captured into `/home/jwk/agent/builds/ub-private-delete-daemon-v1/artifacts/`
before rustc releases the Cargo lock. No server binary is rebuilt.

The build requires the retained full-v2 return.json/source/artifacts and pinned
A_export_real_rootfs_v1.py helper, existing offline Rust/Cargo/native dependencies,
and 24GiB free reserve. It refuses a local owned live FC and preserves existing
partial output rather than auto-retry. It does not observe or stop peer Guests.

Success: UB_PRIVATE_DELETE_DAEMON_BUILT_TESTED_NOT_DEPLOYED.
Failure: STOPPED_PRIVATE_DELETE_DAEMON_BUILD_PRESERVE_OUTPUTS.
Return BEGIN_PRIVATE_DELETE_DAEMON_BUILD_REPORT through
END_PRIVATE_DELETE_DAEMON_BUILD_REPORT. Logs and progress remain in that new
build directory. The artifact SHA is unknown until native compilation completes.

No SDK calls, kernel/module changes, Guest command/create/delete, service restart,
provider retirement or pending-journal reconciliation occurs. Existing A deletion
remains unresolved. Do not overwrite the running daemon or restart it around
live devices from this build result. A separate scoped recovery and versioned
deployment step must first account for the existing resources. Genuine kernel
DEL_DEV and full Guest lifecycle remain pending, even if all unit tests pass.
