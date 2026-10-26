# Independent demand native build v4 — prepared, not executed

This fixed v4 includes failed-reader preservation, local failure diagnostics,
4/16/64 KiB host-page alignment for direct tail reads, and failed-launch ownership preservation, pinned at core
509f806dcb0381683236675e7675059b5f623619. Earlier v1/v2/v3 entries and directories
remain preserved; v4 never reuses or deletes their partial output. Native tests
still have to execute on target. Local Clippy passed for the daemon and
OverlayBD scope; the full Runtime check reports six existing pmem-related
lints in files left unchanged by this work, so it is not reported as passed.

`A_build_demand_ub_runtime_v4.py` is a build-only entry for **A/server1,
ordinary jwk (UID 1204/GID 1205), zero capabilities**. Default invocation
prints a plan. Only explicit `--run` starts local native tests/builds.
No native build has been started by the assistant.

Exact entry size/hash and source revision are recorded in
`demand-runtime-build-v4-packet.json`. It reconstructs the pinned demand source
tree from preserved full-v2 source files plus sixteen embedded changed/new
files. All 883 file contents are individually SHA256-checked. It does not
checkout, edit or rebuild inside the full source directory.

## Isolation and reuse

Everything new goes under `/home/jwk/agent/builds/demand-ub-runtime-v4`:

- `source/`: the distinct demand source tree, including provider and tests;
- `target/`: an independent Cargo build target;
- `artifacts/`: captured new server and uvm-ublk-daemon;
- `tmp/`, phase logs, capture receipts, `build-progress.json`, `return.json`.

The existing verified native toolchain, offline Cargo package cache and
explicit RocksDB/Snappy/clang dependency paths are reused. The shared full
Cargo target is not written; this means native dependencies may need compiling
again in the new target. No completion-time guarantee is made. Require at
least 24 GiB free disk, and stop rather than deleting any existing build.

The full-v2 success receipt is checked first. Full captured and deployed
server/daemon hashes and file identities are checked before and after the
build. Retained CLI, FC, kernel, tools and SDK adapter are verified and reused.
No existing binary, configuration, provider object or entry is replaced.

## Stages and stop conditions

1. Check platform/user/capabilities, prior full provenance and absence of an
   existing demand build directory. A read-only `/proc` guard refuses a local
   running jwk Firecracker before hashing full binaries and before each test
   or build phase. This does **not** prove the peer or the whole machine is
   idle, nor prevent someone starting a Guest during a phase. Explicitly run
   this build outside the measurement window; it is not part of an automatic
   comparison pipeline.
2. Reconstruct exact sources and verify frozen Cargo.lock.
3. Run demand provider concurrency/lifecycle, response-failure and direct
   catalog tests without the SDK. The new Linux-only direct-source test must
   execute and pass, including a short EOF tail and actual O_DIRECT FD flags.
   It creates only its own small temporary file. No cache eviction is used.
   Fixture write cache is not a measured UB/PageCache benefit.
4. Run actual OverlayBD UB wire/lease and binding tests, requiring the demand
   manifest pool/generation test by name. Offline, locked dependencies.
5. Build server and daemon with rootfs read tracing. The rustc wrapper captures
   the uniquely linked AArch64 output before releasing Cargo's lock. Capture
   receipt, source manifest, size and SHA256 must agree.
6. Recheck retained full artifacts and dependencies; save build results.

Each phase intent/result is saved atomically to `build-progress.json`; an
interrupted or failed phase remains identifiable. Unknown prior output is
never removed to enable a retry. Failed builds retain source, logs and partial
artifacts under the same directory for review.

Expected build-only success is
`DEMAND_UB_CORE_BUILT_TESTED_NOT_DEPLOYED`. Failure is
`STOPPED_DEMAND_UB_BUILD_PRESERVE_OUTPUTS`. A successful build still has
`SDK_called=false`, `Guest_created=false`, `servicesChanged=false`,
`kernelChanged=false`, `twoNodeGuestAccepted=false`, and `netSavingsBytes=null`.

## Remaining gates

This entry does not publish/import a demand UB pool, create coordination,
deploy a Runtime, create a Guest, change kernel/modules or retire full objects.
Native test success and resulting binary hashes have not yet been obtained.
The importer still needs an explicitly authorized reliable metadata channel;
no tunnel/SSH/port is created. Real UB concurrent visibility, demand Guest
acceptance and accounting of the entire actual pool remain separate tests.
Full mode remains the priority for comparative field data.


The retained full-provider launchers hold per-node exclusive SDK guards. This
build does not change or bypass them. Concurrent full/demand provider deployment
therefore also requires an explicitly reviewed SDK coexistence/ownership policy,
in addition to the metadata-channel and capacity gates. A successful build is
not authorization to initialize another SDK client beside the retained provider.


## Additional v4 lifecycle gates

Before building the server and daemon, v4 executes five actual orchestrator
`ub_failed_launch_` tests, the three existing `cleanup_failed_launch` rollback
tests and the existing delete-stop-retry test. Every required test must appear
as `... ok` in its native Cargo log; zero matched tests cannot pass this gate.
The candidate preserves backend handles/read permits after unsuccessful stop,
records Killing for explicit deletion retry, and quarantines metadata/identity
conflicts. No failed launch volume capture is published on retry.

Local ARM64 library/test compilation has passed separately for this demand
candidate and the full expansion candidate. The new Rust tests have not been
executed on Linux. Clippy still reports six inherited pmem-related lint errors;
there is no whole-Runtime Clippy pass. A Windows shared build-cache collision
was invalidated and the demand source check rerun; this target entry uses its
own Cargo directory throughout.

Ownership retention is in-process only. Crash recovery and quarantined
identity reconciliation are not implemented by this patch; a shutdown error
cannot keep a service manager from terminating the process. The existing full
Runtime binary remains unchanged, and this build does not deploy the candidate.
