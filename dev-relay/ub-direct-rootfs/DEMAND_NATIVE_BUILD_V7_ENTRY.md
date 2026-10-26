# Independent demand native build v7 — not executed

Core is pinned to `85709c7550124cde1fe9ef3999dda42215f2e1e7` / local
`8c900e5d22d9d331b3e1b82a7a95287ebc58f874`. The exact entry SHA256, file size,
source tree and per-file reconstruction are in `demand-runtime-build-v7-packet.json`.
All v1–v6 entries and the preserved full version remain available. No demand
native build has been reported executed; do not run all historical versions.

`A_build_demand_ub_runtime_v7.py` is for A/server1, ordinary jwk UID1204/GID1205,
with zero capabilities. Default invocation prints PLAN_ONLY. Explicit `--run`
performs native unit tests and builds only. It does not initialize an SDK,
allocate/import a pool, deploy, start a Guest, restart a service, modify a
kernel/module or provide cross-node transport.

## Isolation and reuse

New files use `/home/jwk/agent/builds/demand-ub-runtime-v7/{source,target,artifacts,tmp}`.
The source is reconstructed from retained full-v2 files plus verified deltas.
The full source, Cargo target and deployed artifacts are not overwritten. The
verified native toolchain, offline Cargo cache and RocksDB/Snappy/clang paths
are reused. Dependencies can require compilation in the separate target;
require 24GiB free and do not remove old outputs to satisfy that gate.

The existing full-v2 build provenance and retained CLI/FC/kernel/tools/adapter
hashes are checked. A's captured and deployed full server/daemon identities
must remain unchanged before and after the build; this does not reobserve B.
No native demand binary SHA is currently available. A local owned-Guest guard
runs before expensive stages; arrange the build outside comparison windows.
This guard does not prove the peer or entire Host is idle and cannot prevent
other tasks starting later.

## Native success gates

- Provider lazy/cache/Reader, parallel, residency, payload and direct-catalog
  tests. Required capacity-wait and metadata-stop cases must appear as passed.
- The actual Linux O_DIRECT scratch-file/tail case must execute, not skip.
- OverlayBD wire/lease and binding tests, including demand-manifest validation.
- Four production `ub_retention::tests` cases: retain unresolved directories,
  refuse marker overwrite, preserve normal cleanup, and Unix owner-only mode.
- Five orchestrator failed-launch ownership cases, three existing rollback
  cases and the existing delete-stop-retry case.
- Build trace-enabled server and daemon; capture their exact produced bytes
  before the Cargo lock is released, and verify the preserved full artifacts.

Missing expected tests or zero matches cannot satisfy the gates. Guest300/CLI330
semantics are unchanged. The expected success status remains
`DEMAND_UB_CORE_BUILT_TESTED_NOT_DEPLOYED`; failures retain the progress journal,
logs and partial files as `STOPPED_DEMAND_UB_BUILD_PRESERVE_OUTPUTS`.

## What the new core change establishes

Only an object dropped while required UB rootfs Runtime permits remain
disables TempDir cleanup and writes private `ub-rootfs-unresolved.json`.
The marker contains exact bound generations and process/device/path hints;
it authorizes no SDK retirement. File creation is exclusive, and an error
writing the marker still preserves the directory. Confirmed normal stop
clears permits and keeps normal directory cleanup. Native-pmem and memfile
cleanup logic is not changed by this condition.

Three portable tests executed the actual production helper against real
temporary files locally. ARM64 Runtime and test-code checks passed for the
full candidate and demand candidate. The Unix-only mode test and real
FC/ublk failure path remain unexecuted. Scoped ARM64 Clippy now passes for agentenv and uvm-ublk-daemon library/test
targets with overlaybd/rootfs-read-trace and -D warnings. This is not a claim
that every workspace target/feature or native hardware test passed.

The marker does not preserve kernel ownership across process exit, prove
PID/startTicks stability, or implement automatic quarantine recovery.
Independent reconciliation is still necessary before cleanup/restart.

## Deployment and experiment gates remain separate

Full mode stays the immediate data priority and is not replaced by this build.
The existing full-provider SDK guard is not bypassed. SDK coexistence, actual
pool capacity, an explicitly authorized reliable metadata channel, two-node
UB visibility and the demand real-Guest small demo remain separate gates.
Fixed-pool filling is not on-demand physical allocation. No native Guest
acceptance, sixteen-Guest completion, physical charge or net savings is claimed.


## v7 source-only cleanup

The previous six lint errors were removed using equivalent inclusive integer
ranges and the existing unsigned flag type. The unresolved marker now uses
RuntimeReadLeases::replicas(), removing the redundant added accessor. No
permission, supported-version set, mapping, timeout or lifecycle policy was
relaxed. The original pmem branch/deployment remains fixed; the experimental
candidate includes the equivalent shared userspace validator expression change.
The native build and hardware gates above are unchanged and unexecuted.
