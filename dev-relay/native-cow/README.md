# Native CoW experimental relay

Coordinated build preparation: `A_prepare_release_v4.py --run`.
Core source: `6cdac56ed70284e89693e7bda0470a43ad9bd0b5`. Packet SHA256: `f9c80889c21e041c1b28420889cb8acd4270eed33ebc6a442cf0114c272f4ece`.

This uses a new native-release-v4 build directory, finishes the already resized
rootfs copy without repeating the 64 GiB copy or resize, then creates a new compact
image containing the v3 static DAX execution marker. The final image is rehashed
even when reusing a completed preparation receipt. Runtime, CLI, daemon, verifier,
Firecracker and native protocol tests use coordinated pinned source and existing
offline build caches. Image failure is reported independently of binary builds.

Outputs: `/home/jwk/agent/builds/native-release-v4/return.json`, per-phase logs and
`artifacts/`. Use only the report's `finalImage` when `rootfsReady` is true.
Failed or partial directories are preserved; this build entry does not overwrite
them or automatically retry them. Previous services and deployments stay intact.

This is build preparation, not a service activation or hardware acceptance run.
No SDK, Guest, mount, ublk allocation or service changes are performed here.
The native RAM private CoW implementation is still outstanding for the tested
NC device FD. Native pmem capture/restore/Fork and execution from shared lower
remain pending hardware validation. Keep immutable bases retained independently
of Guest lease completion; content references are not distributed reference counts.

`cow_accounting.py` contains tested set/accounting primitives, not a standalone
hardware collector. It refuses cross-node PFN comparisons and incomplete net
accounting. A successful preparation must not be reported as positive savings.
