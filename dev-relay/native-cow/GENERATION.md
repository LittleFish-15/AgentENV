# Real rootfs generation and legacy experiment handoff

This phase uses production provider sources from core
`099201ee8aea64dd0a8380befeca1b7108b8338a`. The coordinated Runtime/FC build stays
at `6cdac56ed70284e89693e7bda0470a43ad9bd0b5`: the newer core commit changes only
the Python provider control reply handling, its tests and documentation. It does
not change the Runtime/FC ABI, Rust source or C++ adapter. Prepared receipts
identify both `coreCommit` (Runtime) and `providerCoreCommit` explicitly.
The C++ SDK adapter is identical to
the source previously compiled and executed in the B native-pmem experiment.
The new scripts themselves have not run on either target host.

## Preparation and launch order

1. Prepare A with `native_provider_v4.py prepare --node node-a`, the successful
   coordinated build/image receipt and the received original source config.
   It compiles the adapter against the pinned installed SDK headers/library,
   creates a v3 binding to the verified executable compact image, and records
   exact source and binary hashes. It makes no SDK call.
2. Transfer A's prepared binding and its SHA256. Prepare B with the same script,
   B's received coordinated build receipt, and `--owner-binding` plus
   `--binding-sha256`. B preparation records an import role only. It does not
   need the new live owner manifest yet.
3. Both prepared entries must match the handoff helper's pinned candidate.
   Install the identical `legacy_provider_handoff.py` at
   `/home/jwk/agent/legacy_provider_handoff.py` on both nodes. A runs
   `transition-a --run`; this is the explicitly mutating legacy retirement
   boundary. A uses the existing authenticated SSH path to `jwk@agent1` with
   strict host-key checking and no password prompt. The helper is not run by
   the development agent against the servers.
4. After successful handoff, A's `native_provider_v4.py start-plan --node node-a
   --run` prints a scoped root block for a new capability-free provider unit.
   The unit calls the SDK to publish the real compact image. Existing UB
   daemons are not restarted or reconfigured. Wait for the new provider's
   journal to report `serving`; a systemd submission alone is not success.
5. Transfer A's new `provider/replicas.json` and its byte SHA256. B's
   `import-manifest --node node-b --manifest ... --manifest-sha256 ... --run`
   validates the exact new content, reader identity and mapping layout before
   writing it. Then B's `start-plan` prints its scoped import-unit block.
   B does not allocate or delete A's object.
6. Runtime preparation uses each node's newly prepared v3 binding. Seed original
   rootfs inputs before activating either new native Runtime. Guest lifecycle
   and same-workload measurements follow only after both providers are serving.

Sessions are `/home/jwk/agent/r/up-a-v4` and `/home/jwk/agent/r/up-b-v4`.
Preparation writes `prepared.json`, `config.json`, `binding/binding.json`,
`compile.log`, the compiled adapter and the pinned provider sources. Runtime
SDK intent/outcome lives in `provider/owner.json`; publications and imports use
fresh directories and preserve failed attempts instead of changing names to
hide uncertain allocations.

This field entry accepts one aligned real image no larger than 2 GiB. Logical
requests and post-map coverage guards are recorded separately. Host available
memory is checked before the SDK call, and the new unit has a process memory
limit. These are not a service-enforced UB physical-memory quota and do not
prove the actual physical cost. Physical sharing and net savings require the
later measurements. Neither entry enables native RAM private CoW.

## Why the legacy handoff holds a lock on B

The old 64 MiB generation is identified by its exact manifest digest. B must
show that its latest pair-test import was explicitly released and finalized,
with successful post-read integrity verification. A detached B worker then
holds the same node-wide SDK mutex used by the earlier scripts. A live,
nonce-bound control exchange authorizes A's single retire request while B
continues holding that mutex. This prevents the coordinator from reimporting
the old generation during its retirement.

A retires only through the pinned old provider's local control protocol. It
does not kill the publisher, remove sockets or issue its own SDK deallocation.
Completion requires the exact object's deletion acknowledgement, finalization,
integrity check and release of A's SDK critical section. B releases its fence
only after receiving that confirmed owner state. Both next provider candidates
must already be prepared for identical content before the old object is retired.

The old small test image and historical result files are preserved; the old UB
publication is deliberately retired to free its SDK critical section. This is
not an instruction to retire a business publication or any unknown object.

`resume-a --run` reconciles the saved transaction. Once a retire intent exists,
it never resends retirement. A lost reply leaves the B fence and journals for
reconciliation. An explicit refusal with an unchanged serving owner can release
the fence without deleting the old object. A completed resume does not contend
with a newer SDK owner. Failed pre-authorization setup and a dead fence worker
are preserved for inspection; there is no blind process/socket replacement.

## Retaining and eventually releasing the new base

Keep the new providers running while committed native snapshots or paused/running
Guests need the base. Runtime rollback preserves these provider publications.
There is no automatic distributed snapshot garbage collection or reboot recovery.

If a control client disconnects while receiving a refusal, the provider keeps
serving. If cleanup and the durable release receipt have completed, losing the
completion reply preserves the released state. Actual cleanup failures remain
unresolved. The coordinator must inspect those recorded outcomes instead of
repeating retirement merely because a reply was lost.

The wrapper records and fsyncs a one-shot retirement intent before connecting to
the control socket. A prior intent with no complete released owner journal is
not sent again. Completed journals are validated against the exact manifest,
role, object/import record, finalization acknowledgment and post-release base
integrity. This allows confirmation after a lost reply without another SDK
operation. A missing B peer receipt can be reconstructed only from that complete
exact-generation evidence; incomplete or mismatched journals remain blocked.
Publisher peer receipts are validated before recording a new retirement intent.
An explicit refusal after the intent still requires review; this is not an
automatic retry loop or distributed failure detector.

The new provider wrapper's `retire --node ... --run` requires a quiescent cohort,
an empty running/paused API inventory and no retained records in this isolated
POSIX snapshot repository. It refuses before contacting the provider when
snapshot records remain. Release B first, transfer its **new generation** release
receipt, then retire A with `--peer-receipt`. The underlying provider also refuses
active local leases and mismatched remote release receipts. This contract covers
the controlled two-node experiment, not unregistered consumers on other nodes.

Local validation covers the nonce/receipt state machine, partial cleanup and
explicit refusal, lost terminal replies, already completed recovery, exact B
import identity, pre-SDK guards and generated root-unit scope. It does not prove
real SSH persistence, Linux locking, new SDK publication/import, Guest DAX
execution, capture/restore/Fork or positive memory savings on the target hosts.
