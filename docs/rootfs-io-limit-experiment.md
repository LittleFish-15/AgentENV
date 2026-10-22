# Rootfs ublk I/O limit experiment

This experiment starts at original AgentENV commit
`ae9c62693839ce7effa2b45df31c0039ae4f9fbc`. It does not contain the UB or
cross-node CoW implementation.

Set the following value in the original Runtime configuration for the treatment:

```toml
[ublk.overlaybd]
rootfs_max_io_kib = 64
```

The default remains 256 KiB. The setting applies to sandbox rootfs devices in
both cold creation and snapshot restore. Extra drives, memory snapshot devices,
raw devices and default pool prewarming retain their existing 256 KiB limit.
The pool only reuses devices with the requested I/O limit. This check remains
mandatory when the kernel supports resizing device capacity: capacity resizing
does not change the device's I/O buffer size.

The Runtime uses an explicit protocol extension for nondefault limits. An old
daemon rejects the new request tag rather than ignoring an optional field and
silently creating a device at the old limit. New daemon devices must report the
requested limit in the kernel device information after startup; a mismatch
fails creation and uses the existing cleanup path for that owned device.

This setting changes the maximum individual ublk I/O size, **not** the remote
file cache refill size, filesystem readahead policy, Linux page size, or memory
startup-pack block size. The lower-file format and merge operations may issue
backing-file reads of different sizes; a lower read histogram alone does not
prove the logical ublk request limit.

## Validation and comparison

Run the configuration, protocol/client and pool matching tests. Build both the
Runtime server and daemon; do not deploy a new Runtime with an old daemon.
Before replay, verify each owned rootfs device's kernel queue limit is 64 KiB,
and the owned memory devices retain 256 KiB. A missing or mismatched limit is
an experiment admission failure, not a passing treatment.

Keep the workload, snapshots, eight-Guest concurrency, continuous replay mode,
cache preparation and sampling schedule identical to the previous four-template
original experiment. Reuse the same read observer and retain its fingerprint
separately from this source revision. Collect host Cached/Dirty/Shmem, complete
lower residency, attributed lower-read residency and intersections, upper
sizes/residency, and per-process RSS/PSS. Mark sampling gaps and trajectory
failures. Compare aligned phases and per-template windows without summing peaks
that occurred at different times. Host background I/O remains a confounder.

## Exact restoration

Before temporary activation, preserve the original server binary and complete
configuration bytes, permissions and ownership, together with their SHA-256
digests. Preserve the existing daemon binary. Record the candidate digests and
the service/process identities used in the experiment.

After the experiment's Guests and readers have exited, restore those original
binary/configuration bytes and verify their digests before restarting the same
original service. Changing the setting to 256 is a behavioral control; it is
not a substitute for byte-for-byte restoration of the original binaries.
For source rollback, reverse only this experiment's patch against matching
candidate hashes. Do not reset unrelated work or any cross-node CoW branch.

Target Linux builds, actual kernel queue settings, Guest execution and cache
effects require target execution evidence. Source changes or local unit tests
alone do not establish those results.
