# Two-node rootfs lazy-cache retry v2

This is a fixed-generation retry for the already prepared four-template experiment.
It is not a fresh-host installer. Runtime/Firecracker binaries and private images,
snapshots, replay inputs and the dedicated SSH configuration are reused locally.
The initial ordinary/lazy run must be explicitly cleaned up first.

The single Python entry embeds and verifies 15 public helper modules. It prepares
isolated launchers, reuses the prior verified SDK adapter and chunk catalog, then
prints one fixed root supervision block per node. Both root terminals and the
ordinary A coordinator terminal remain open until completion. A and B each run
four templates with two Guests per template, first with UB off, then lazy UB on.

No original service is restarted or modified. No driver or kernel setting is
changed. No global drop_caches is performed. Scoped advice and mincore apply only
to the retained independent lower copies before each round. The original Runtime
inventory must remain empty while the test is running.

This generation uses new work/provider directories and a new launcher subdirectory.
It preserves old launchers and reports. An existing partial v2 stage is not blindly
overwritten or retried. SDK/header identity and old release/content evidence are
checked again. Preparation does not call SDK initialization or allocate UB.

Guest command timeout remains 300 seconds, CLI timeout 330 seconds. The proxy
connection budget is 360 seconds. Memory accounting supports mounted cgroup v1/v2
and retains readable Host fields if PSI files are unavailable.

Root replies reside under a protected /run generation. Confirmed failed operations
leave a cleanup-only channel; absent or invalid acknowledgments are never retried
implicitly. A foreground coordinator mutex prevents concurrent manual cleanup.

Normal and failed-run cleanup waits for Guest quiescence, stops exact owned Runtime
and proxy processes, retires B before A, finishes both root supervisors, then closes
the owned metadata transport. Unknown pin/SDK/request states preserve resources
and evidence instead of claiming cleanup. Such conditions still need explicit
reconciliation; the entry cannot guarantee automatic recovery from node loss.

Commands, once the pinned file has been placed in its declared directory:

```
/usr/bin/python3 -I -B /home/jwk/agent/lazy-four-v2/lazy_four_rollout.py run-a --run
```

Do not restart run-a after a failure. Read return.json or preparation-failure.json,
cleanup.json and logs in /home/jwk/agent/r/lazy-four-rollout-v2 first. If the original
coordinator has exited and the exact root supervisors remain available, the same
pinned entry provides stop-a --run. This only attempts the known generation's
remaining cleanup; unresolved requests and unknown pins still block unsafe release.
Old images, snapshots, input files, logs, source files and SSH keys are retained.

Full success is V2_OFF_LAZY_COMPARISON_AND_RELEASE_COMPLETED. Comparison files are
in the work directory's comparison/ subdirectory. Completed cleanup alone is
V2_OWNED_RESOURCES_RELEASED and must not be confused with completed replay.

This experiment validates only ordinary block-path rootfs lazy caching. It does
not implement native Guest RAM private CoW or remove Guest filesystem cache. Off
uses the same modified binaries with UB disabled, not the historical original
binary. Whole-lower residency is not per-Guest accessed/resident intersection.
SDK coverage subtraction remains a budget model, not measured physical savings.
Full physical net savings stays NA without complete nonoverlapping physical data.

Local validation: 47 Python checks, including the actual coordinator control flow
with modeled external nodes/processes, cleanup ordering/refusal, embedded hash
closure, reuse identity, root receipt trust, proxy deadlines and metric readers.
Windows filesystem/ownership tests model Linux-specific operations. No target
execution, systemd, UB SDK or hardware acceptance is claimed for this v2 entry.

The provider code is pinned to core 775b7ae8ad01c167ed84f77ae2a0b3c1fee44fb7,
while Runtime/FC binaries stay at the retained 32ce build. Authenticated completed
chunk releases no longer require a second journal commit: old released pins may
remain conservatively recorded until the next grant/reader release/freeze. Every
new grant remains durable before reply, and unknown pins never expire. Ten local
modeled chunk reads now require ten grant checkpoints rather than twenty
grant/release checkpoints; no target latency improvement is claimed. Prior 3aa
adapter/catalog preparation is reusable only after exact identity/release checks.

Reports now include per-Guest outcomes/durations and template RAM/FC/upper/auxiliary tables. A failed run produces an explicit partial report when node reports are available. Full acceptance requires per-command exit codes to match off versus lazy on the same node/template/slot; 124/137 remain failures. Identical nonzero results are retained, not called all tests passed.
