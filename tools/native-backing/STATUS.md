# Native backing implementation status

Date: 2026-10-20. **Experimental consumer implementation; final memory-density
objective is not achieved or validated.** The existing layer-sharing mode remains
the default. No deployed service, device permission, SDK or BIOS was changed.
An owned disposable target probe, described below, has now completed.

## Actual target FD result and FC follow-up

The target opened one NC readonly OBMM device through the public SDK lookup ID.
Readonly shared mmap and two marker reads succeeded; seek failed with ESPIPE,
pread and the tested private writable mmap failed with EINVAL. Path reopen lost
O_SYNC. Child exits and SDK unmap/delete/finalize were confirmed. The object used
4MiB logical capacity and reported 128MiB backing coverage, not a measured physical
increment. KVM, Guest, DAX, RAM CoW and cross-node native acceptance remain untested.
EINVAL does not identify the failing kernel branch or rule out all alternative
platform/FC CoW designs.

The existing native consumer therefore **does not support this target device**.
The new [FC patch](firecracker/README.md) implements an explicitly sized readonly
inherited-FD backend that preserves O_SYNC and bypasses path reopen/read/seek.
It refuses native snapshot save/restore instead of persisting temporary FD numbers.
It is not yet connected to a device-aware aenv provider/consumer and is not deployed.
Four new portable contract tests passed and the mapping code/tests type-checked
for Linux ARM64. Full patched FC check was attempted, but the locked micro-http
Git dependency fetch failed with a connection reset; no lockfile workaround was
applied. Full FC integration compilation has therefore not passed.

| Work | Result | Acceptance still required |
| --- | --- | --- |
| Full logical RAM export | Bounded streaming exporter, zero-page holes, explicit size budget, new output only, SHA/allocation output; ARM64 type-check passed against the actual OverlayBD source | Target export and startup/validation cost |
| Native FD consumer | Same-UID SCM_RIGHTS, exact identity/generation/length, readonly/cache checks, whole SHA, child-specific FD inheritance, pinned lease | Actual UB provider and Linux runtime execution |
| RAM restore | Matching linear backing bypasses memory ublk; incompatible config fails without copying fallback | KVM/private CoW, capture reads, discard/free-page reporting, cross-node identity |
| pmem rootfs cold boot | Read-only pmem layers plus private ext4 upper, source binding, address-range budget, EROFS/OverlayFS startup | New immutable tools image and compatible target Guest kernel/images |
| DAX checks | Lower regular-file metadata scan and post-overlay probe; ARM64/amd64 checker builds and ARM64 vet passed | Actual target STATX_ATTR_DAX, shared backing pages and file-access behavior |
| pmem snapshot/Fork | Explicitly refused before VM pause; no false persistence success | Durable read-only image references, provider retention/rebuild and versioned restore integration |
| Actual UB FD provider | Not implemented against an unproven private ABI | Confirm a supported single/range FD contract from installed UB/OBMM; do not scrape internal SDK FD tables |
| Net memory savings/task density | No new result claimed | Full shared-pool/local/private accounting and controlled workload |

## Source findings, not an assertion that UB has no FDs

The fixed ubs-mem source has a real OBMM FD mapping chain: shared-object import
returns backing IDs and unit sizes, then the SDK opens `/dev/obmm_shmdev<id>` per
unit and maps them. Its public named-object interface returns an address, not a
single logical image FD. Its `ubs_mem_fd_get` usage is in the borrowing/debt path.

The missing proof is compatibility: number/ranges of FDs, readable/seekable
capacity, cache mode, private CoW, KVM page handling, and lifetime after handoff.
Merely opening a device FD does not establish these. The current consumer supports
one whole, readable/seekable, cacheable backing FD per image. A segmented or
mmap-only UB device requires additional integration, potentially FC support.

FC currently reopens a backing path. Reopening `/proc/self/fd/N` preserves object
identity but does not preserve O_SYNC. The implementation therefore refuses NC
FDs rather than silently remapping them cacheable. A future FD-aware FC path could
preserve the original open description; platform cache/CoW support must still be
verified. Switching BIOS or device permissions is not part of this implementation.

## What is within aenv, and what is outside it

Within this repository: consumer lifecycle, backing selection, source identity,
image/Guest bootstrap, snapshot references, private-write layout, budgets,
accounting, tests and orchestration. Durable pmem snapshot/Fork is a real remaining
engineering task here; it is **not** described as inherently impossible for aenv.

Outside this repository or requiring target evidence: supported UB/OBMM FD export,
driver mapping/KVM/CoW semantics, cache ownership, target Guest kernel DAX support,
and actual physical-memory measurements. A compatible existing interface may
avoid driver/FC changes; absence of evidence does not prove such changes necessary.

The experimental mode fails rather than publishing snapshots whose pmem state
refers only to temporary child FDs. It cannot yet combine native RAM restore with
a captured native-pmem-rootfs parent. Providing temporary handles without durable
identities would hide a correctness gap rather than complete the objective.

## Validation performed

- 12 portable Python tests executed: canonical image binding, full RAM size,
  mutable-upper refusal, budgets, duplicate objects, preserved outputs, socket
  limits, and actual socket framing errors.
- 5 portable Rust contract tests executed; portable clippy passed.
- 2 sparse writer content/offset tests executed locally; file allocation is not UB physical allocation.
- Linux/ARM64 contract tests (including 2 SCM_RIGHTS tests) type-checked; Linux
  contract clippy passed. The Linux tests were **not executed** on the Windows host.
- Actual FC instance/socket/connector/generated models and scoped-spawn source
  type-checked for ARM64 in an isolated harness. The peripheral MMDS payload type
  was a stand-in. This is **not** a complete AgentENV server build.
- Actual OverlayBD source and the new logical-memory exporter type-checked for ARM64.
- Guest checker built for Linux ARM64 and amd64; Go vet passed. Bootstrap shell
  syntax passed. No target DAX syscall, mount, KVM vCPU, Guest or UB object was run.
- Full Runtime check was attempted, but fetching the exact locked libublk-rs Git
  dependency failed in transport. No Cargo.lock/dependency workaround was committed.

## Next handoff

The prerequisite and owned-FD probes have completed; do not rerun their creation
steps or remove their receipts. Next implement a device-aware provider/consumer
and independent safe content verification, complete a matching FC build, and
validate KVM readonly device mapping before actual Guest DAX. The ordinary SSH
account's KVM access result is not the configured Runtime's permission result.

After the FD contract is established: implement the real provider, complete
durable pmem references/restore, build new EROFS/tools inputs, run native RAM and
rootfs mechanism checks, then compare global memory cost and task density.
Local memfd fixtures must never be relabeled as UB/cross-node acceptance.

A linear logical RAM view must not imply eager allocation of its whole physical
capacity. Exported files and local fixtures preserve zero-page holes, but the UB
provider still needs an appropriate sparse/range/zero-page strategy. Dense UB
allocation of the entire Guest RAM can consume more memory than the original
sparse snapshot. This consumer does not implement that platform view.
