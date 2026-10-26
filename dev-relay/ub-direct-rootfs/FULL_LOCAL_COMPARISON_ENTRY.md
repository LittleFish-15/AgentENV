# Full UB comparison entry: implemented, not target-validated

`AB_full_local_comparison_v1.py` packages the reviewed local comparison path.
Its exact bytes and all ten embedded component digests are in
`full-local-comparison-build.json`. Import and default invocation perform no
target action. It requires an explicit `--run` on the declared node as root.

This is a local phase executor. It does not provide cross-node transport,
synchronized starts, a sixteen-Guest result, new UB allocation or deployment.
No target run has been performed by the assistant. There is no new real Guest
comparison result at the time of this delivery.

## Preconditions and retained scope

- Complete real two-node Guest bundle for the published pair continuation v2,
  including ready and phase receipts, command results and lifecycle journals.
  The embedded verifier recomputes the evidence chain; a status boolean or a
  previously generated verification summary alone is insufficient.
- Both retained original and full Runtime services remain running and empty.
  Their exact server/daemon/CLI hashes are checked. FC hashes must match, actual
  CLI credentials must point to the local process's API_ADDR, catalog hashes
  and lower sequences must match the retained seed.
- Current local full Runtime identity must equal the accepted pair's identity.
  Provider identity and read permits are checked without another allocation or
  replay of the previous Host full-read experiment.
- A separate private allocation ledger is needed, identifying the same owner,
  manifest and eight objects, with unique A export regions and export boot
  identity. Each object has `objectName` and `regions`; each region has `role`
  (`export`), `exportNode`, `exportBootId`, `exportRegionId` and `bytes`. Top
  fields are `version:1`, `mode:full-stored`, `presence:retained`, `ownerId`,
  `manifestSha256`, `objects`. This ledger represents reported retained
  reservation, not measured incremental physical charge. Current scope must
  equal the already reported nineteen 128 MiB regions. Import mappings are not
  billed as a second allocation. The ledger itself is private evidence, never
  embedded into or published with the entry.
- The default smaller scope is the first template, two Guests on each node:
  four Guests across the pair, per variant. The original sixteen-Guest goal
  remains outstanding. Selecting four templates fails the current exact
  coverage gate; the existing eight objects and 4 GiB approval are insufficient.

## Explicit phases and coordination

The interface accepts `--node a|b`, `--phase original|full`, a shared explicit
32-hex `--run-id`, `--pair-bundle`, `--allocation-ledger`, and optional
`--templates 1|4`. The full phase additionally requires `--peer-original`.

After the real Guest pair passes, original phases can be explicitly started
on A and B. Each writes its completion receipt only after local Guests exit.
Each full phase then requires both its own persisted original completion and
the other node's original receipt, with matching controller/run/input identity
and completed creation/release journals. This avoids starting a full phase
while the peer's original phase remains unconfirmed. It does not make starts
simultaneous and cannot establish overlapping sampling windows.

No file transfer or remote execution is performed. With current authorization,
the dependency between original completion and full launch still requires
human relay. The entry is not an overnight unattended two-node controller.
No new commands should be requested while the user is offline.

## Actual operations and persistence

The only Guest mutations are restored sandbox creation and owned deletion.
There is no cold creation, snapshot capture/deletion, UB publication/retirement,
service restart, module operation or cache eviction. The original upper/pooling
policy remains intact. Full UB private devices must disappear before completion.

All phases use the fixed root-owned directory:
`/home/jwk/agent/deployments/agentenv-direct-ub-guest-v1/comparison/full-v1`.
It contains the exclusive controller lock, persistent run journal, and
`original/` and `full/` phase directories. A new run ID cannot reset this state.
An interrupted lock, unknown POST, failed replay, identity change, timeout or
unconfirmed cleanup stops dependent work and retains evidence. There is no
automatic retry/reconciliation entry.

Each phase writes `before-guest-create.json`, per-template lifecycle journals,
`replay.json`, baseline/final samples, `samples.jsonl`, raw command outputs,
actual bindings and a completion receipt. UB additionally requires
`actual-ub-reads.json` with real daemon events for each Guest's image. Actual
read-trace status must show no fallback, loss or failed/cancelled read. Guest
timeout remains 300 seconds and CLI transport 330 seconds.

`local-comparison.json` is written after both local phases complete and compares
the exact workload signature and each command's exit code. It is a local
comparison, not a two-node aggregate or net-savings calculation. Known nonzero
commands are retained and compared; timeout/killed/unknown results stop a phase.

## Measurement boundaries and remaining work

Source ordinary-file residency is measured separately for original and UB
repositories, including ordinary memory snapshot layers. Private upper,
actual ublk devices, whole FC/process PSS, authoritative Guest RAM intervals,
Host counters and retained UB reservation are separate; overlapping quantities
are not summed. Initial sampling occurs before creation and again before
replay; restore time and replay time are separate.

Native Linux mincore/FD/proc behavior has not been tested by this new executor.
Index/decompression/response-buffer subdivisions and transient CLI PSS are not
independently measured; complete physical UB charge and global net benefit
remain NA. Four-template publication/import, capacity approval, reliable
authorized coordination, final cross-node aggregation and real field results
remain outstanding. Existing full artifacts, provider objects and pmem branch
are retained. This executor does not replace the full core implementation.
