# Native backing implementation status

Date: 2026-10-20. **Experimental consumer implementation; final memory-density
objective is not achieved or validated.** The existing layer-sharing mode remains
the default. No deployed service, device permission, SDK, BIOS or live experiment
was changed for this work.

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

Run the single ordinary-user `preflight.py` on the two intended nodes and return
its JSON. It performs no SDK operation/allocation/service change. The next native
probe must use a disposable owned object with a concrete budget, retain the
original lifecycle guards, and stop on unsupported mappings or unclear cleanup.

After the FD contract is established: implement the real provider, complete
durable pmem references/restore, build new EROFS/tools inputs, run native RAM and
rootfs mechanism checks, then compare global memory cost and task density.
Local memfd fixtures must never be relabeled as UB/cross-node acceptance.

A linear logical RAM view must not imply eager allocation of its whole physical
capacity. Exported files and local fixtures preserve zero-page holes, but the UB
provider still needs an appropriate sparse/range/zero-page strategy. Dense UB
allocation of the entire Guest RAM can consume more memory than the original
sparse snapshot. This consumer does not implement that platform view.
