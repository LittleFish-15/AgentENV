# Package actual Guest pair receipts without replaying the experiment

`AB_pair_evidence_package_v1.py` embeds the fixed v2 pair verifier and has two
operations: target-side `collect` and local/offline `merge`. It does not run a
Guest command, call a Runtime/provider API or SDK, transfer files over a network,
change a service, release an object or clear caches. No real capsules have been
collected or merged by the assistant at delivery time.

## Collection

After the existing pair phases finish, collection is explicit as root on each
matching node. `collect --node a|b` prints a plan. Adding `--collect` reads the
fixed `acceptance/direct-pair-v1` files; `--emit-capsule` additionally prints a
compressed transfer block. It does not rerun ready, write isolation, post-exit
reads or checksum verification.

The collector takes a nonblocking shared lock on the pair controller's
`run.lock` while copying receipts. This is separate from the SDK exclusivity
guard, which it never touches. Missing/incomplete phases, unconfirmed API
operations, changed source bytes or conflicting process identity prevent a
successful capsule. It reads only named reports, phase and lifecycle journals,
command intents/results. Raw Guest stdout/stderr, API credentials and private
workload files are excluded. The raw JSON bytes of each included receipt are
retained with their hash so packaging cannot silently alter their meaning.

The provider PID/startTicks/boot must match the ready report. To construct a
proper allocation ledger, collection also reads saved object-to-device mapping
metadata and small current sysfs role/size/endpoint attributes, with stable
device identities. Older returned mapping reports lacked the boot namespace
needed by the ledger; this supplements that metadata without a VMA/PFN scan,
UB payload read, ordinary lower read or Host benchmark. The ledger bills A's
`export_info/node_mem_size`, keeping the region window size separate; it never
substitutes payload or imported mapping length for reserved bytes. Missing kernel metadata
is recorded as unavailable rather than zero. Conflicting identities still fail.

Outputs remain private under:
`/home/jwk/agent/deployments/agentenv-direct-ub-guest-v1/acceptance/direct-pair-v1/evidence-a.json`
or `evidence-b.json`. Existing output is preserved. The optional transfer block
contains these private experiment receipts and belongs in this task's return
channel, never a public repository or the report thread without review.

## Offline merge

`merge --a <capsule-or-return-text> --b <capsule-or-return-text> --output <fresh-dir>`
accepts saved JSON capsules or their compressed return blocks. It verifies
bounded decompression, raw file hashes, exact local phase completion, current
provider epochs and the original complete two-node receipt chain. It then
checks A export/B import segment identities and endpoints against the actual
Guest-bound object/generation set.

Output files are:

- `pair-bundle.json`: exact input for the already packaged local comparison
  executor and pair verifier;
- `allocation-ledger.json`: A export region reservations counted once by
  export boot and region identity. B import windows are not added as copies;
- `verification.json`: completed receipt checks and accounting scope.

If device metadata is unavailable, the Guest receipt chain can still be
verified and saved, but no allocation ledger is emitted. Reservation bytes and
region count are null. The comparison executor's accounting prerequisite is
then still unmet; packaging does not bypass it.

Successful merge means the supplied target receipts satisfy the contract. It
is not an independently repeated hardware run, an atomic two-node memory
measurement, whole-system net savings or authorization for sixteen Guests.
No synthetic test fixtures are written as experiment evidence.

This reduces final evidence collection to one fixed invocation per node and
one offline merge, after the four dependent pair phases have actually finished.
It does not remove those phase dependencies or provide an authorized automatic
cross-node channel. Do not collect or request user relay while the user is
offline; all target operations remain human-mediated.
