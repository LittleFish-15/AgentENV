# Content-read and UB ready-set candidate

Core: `6ab53dd2e1f33cb63cbad63eb62a3388494e382c`. This contains the native archive changes from `7120140` plus optional content observation.

`A_build_content_observer_v1.py --run` uses the existing ordinary-user offline build environment and a fresh `builds/content-observer-release-v1` directory. It tests native archive files, the provider suite and observer records, then builds matching `server` and `uvm-ublk-daemon` with `overlaybd/rootfs-read-trace`. Full logs, fixed source identity, per-phase time bounds and copied artifact hashes are retained. Default invocation is plan-only. Existing installed binaries, images, snapshots, FC, verifier and services are preserved. This is a build candidate, not an installed experiment.

The observer attributes successful reads to the actual rootfs config and stored content. It records fallback explicitly. A version-2 header and bounded status counters expose drops, errors and unsupported context propagation. Source identity must be mapped to the real sandbox before grouping. The provider residency command paginates an immutable ready-content snapshot through the original 4KiB metadata protocol. Observation expiry/replacement never releases a data-plane pin. Owner clock fields must not be compared directly with another node's monotonic clock.

`content_residency.py` contains tested interval accounting for per-Guest actual accessed ranges intersected with one ready set. It distinguishes full ready content, accessed union, at-least-two shared content, all-Guest intersection and duplicate logical participation. Input traces must have complete sequence/status, matching bindings and a coordinated sampling window; the caller must establish this evidence. It is not yet wired into the field coordinator. It cannot reconstruct access sets from old aggregate counters and cannot label whole-file residency as accessed intersection. Local file mincore sets need the corresponding local-read parser and exact inode-to-digest mapping.

These outputs are logical content overlap, not measured net physical memory savings. Do not compare PFNs across nodes, count the same UB pool twice, or add Guest file cache again on top of Guest RAM. Source fallback, incomplete traces, missing timing alignment and absent physical accounts remain unknown. The stable rootfs retry at `719ea4c` is unchanged and does not enable this observer automatically.

Local checks: full ARM64 project check with tests and feature enabled/disabled; 49 provider Python tests; six portable actual-source observer tests and focused Clippy; five interval tests; four build-packet tests. Linux-specific observer tests are compiled, not executed locally. No target host, SDK or Guest was accessed. True memfile private CoW remains unimplemented.

## Isolated staging component

`prepare_observed_service_v3.py` and `stage_observed_service_v3.py` prepare a new
`libexec/observed-v3` tree under the retained deployment. They require the exact
successful candidate build receipt, verified ARM64 binaries, inactive experiment
units and the prior released Guest/UB receipts. The new server and daemon, runtime
config, definition, launcher and installation receipt are separate files. Old
installed binaries, config, credentials, definitions and launchers stay intact.
The existing CLI, FC, verifier, snapshots and images are reused with their pins.

The observer spec binds the existing lower inodes and content identities and uses
`trace-{pid}.jsonl` inside a new private observation directory. Sequential daemon
runs therefore preserve separate trace/status files under one fixed spec. Staging
does not start services, allocate UB or create Guests. Partial stages are retained
and are not blindly overwritten. Rollback of an activated candidate requires
confirmed Guest/process shutdown before the preserved old launcher can be used;
staging itself needs no restoration of old files.

Four local staging checks cover both node definitions, actual installed-check
path selection, rejected build provenance and an inode/content spec over a real
local fixture (Linux ownership is modeled on Windows). Root supervisor/cohort
version-3 integration and coordinated access sampling remain pending. These
components are not a standalone full two-node rollout command.
