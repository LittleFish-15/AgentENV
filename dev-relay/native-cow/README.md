# Native CoW experimental relay

This branch contains lab execution tooling. Core/main remain unchanged.

## Rootfs component comparison

`rootfs_cache_compare.py --node node-a --dax-pass-report <actual-pass.json>
--guest-config <actual-config.json> --run` prepares a private tools-image copy
and prints a reviewed root block for a new capability-free KVM unit. Requires a
real completed DAX pass, exact FC/kernel/base and passing seccomp policy pins.
No existing service or UB publication is restarted. The operator keeps the UB
publisher running. The script calls no UB SDK and creates at most two Guests at
once, six in total: block N=1, pmem N=1, block N=2, pmem N=2. Each reads the same
8 MiB synthetic file and holds for 30 seconds. All signed results are retained.

It measures Guest Cached before/after, selected FC RSS/PSS when readable, scoped
unit memory charges and regular-file cache observations. Inputs are hashed and
prewarmed. UB remains alive in both modes and outside the measurement unit;
global UB physical cost and global net savings remain NA. This cold-boot
component test is not the original snapshot-CoW baseline, memfile private CoW,
or cross-node acceptance. It writes results/return.json and results/report.md.

The self-contained packet embeds source and the project-built static ARM64
statx query helper (its Go source is also included). The helper runs inside the
new Guest only. No production binaries, credentials, active UB manifest,
captured data or private benchmark is published. Source/helper hashes are
verified during extraction. Core branch is not modified.

Packet SHA256: `f7294ddb13a76cc147a8958a80fa683d34a3e400916598b0cdb407b664f06384`

## Earlier compatibility runners

The getpid-v3, tgkill-v4 and futex-v5 field runners are retained for provenance.
They add observed, scoped GNU ABI rules while preserving default-trap policies.
Do not rerun a completed case. The v5 complete pass is a prerequisite for the
comparison; it does not itself measure memory savings.
