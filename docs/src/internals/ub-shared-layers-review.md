# UB snapshot and rootfs layer reuse: implementation review

Status: experimental implementation; target SDK, ublk and Guest acceptance is
pending. Baseline: `20260924@ae9c62693839ce7effa2b45df31c0039ae4f9fbc`, workspace
0.2.2. Review input: the 3.0 AgentENV-only cross-node CoW design.

## Source facts and design corrections

Line references below refer to the unchanged baseline, not subsequent insertions.

| Claim | Source evidence | Consequence |
|---|---|---|
| Same-node memory restores share a read-only ublk device | `src/sandbox/ublk/device.rs:582`, `:606`, `:682`, `:752` | Retain this device pool and its reference lifetime; it is a node-local pool. |
| RAM restore uses the existing File backend | `src/sandbox/firecracker/sandbox.rs:1967`; `instance.rs:575` | UB supplies layer bytes to OverlayBD; it is not a new FC RAM backend. |
| Rootfs has reusable immutable lowers and a private upper | `src/sandbox/firecracker/sandbox.rs:1240`, `:1803`, `:2048`; `storage/overlaybd/src/image/image_file.rs:269`, `:550`, `:593` | Extend the design's memory-only data source to rootfs lowers. Never share writable uppers. |
| A committed snapshot contains more than RAM | `src/snapshot/types/snapshot.rs:322`; `repository/backends/posixfs/runtime.rs:83`, `:87` | VM state, RAM, rootfs and drive/volume dependencies must remain capture-consistent. |
| Capture, durable publication and runtime resolution already exist | `src/snapshot/manager.rs:125`, `:300`; `src/sandbox/firecracker/sandbox.rs:383` | Keep durable layer identities and catalog semantics. UB residency is disposable derived state. |
| The file abstraction is an insertion point before format parsing | `storage/overlaybd/src/io/virtual_file.rs:49`; `image/image_file.rs:550`, `:643` | Preserve tar/ZFile/LSMT adaptation. File offsets are not guest physical addresses. |
| Existing fork is node-local | `src/sandbox/firecracker/sandbox.rs:448`; `services/gateway/internal/server.go:168`, `:441` | Do not describe the old fork API as cross-node placement. Initial acceptance uses directed restores on independent Runtimes. |

The supplied public ubs-mem source (`dd7de593843bdc1e9ef4c4660bc86ff3ec499219`)
provides `ubsmem_shmem_allocate` returning a status and `ubsmem_shmem_map` returning
an address (`src/app_lib/include/ubs_mem.h:130`, `:179`). Its ordinary MAP_PRIVATE
request is rejected (`src/app_lib/mxm_shm_lib/mxmem_shmem.cpp:465`). SDK internals
may assemble several memid mappings (`RackMemShm.cpp:131`, `:146`); an internal FD
is not a public whole-object FC memfile. This implementation neither modifies the
SDK nor relies on such an FD.

**Experiment fact:** a user-relayed two-node NC4MiB experiment created one named
object on A, imported it without allocation on B, verified random data both ways,
unmapped both sides and received the owner's SDK deletion acknowledgement. That
does not prove layer-format compatibility, KVM compatibility, CoW or performance.
Full private terminal evidence remains outside this repository.

**Assumptions:** callers publish committed immutable stored files; no external
authorized writer mutates ready UB objects; target nodes share the tested UB
domain and compatible snapshot ABI. Read-only importer mappings are a software
protocol, not a global hardware seal. Provider/daemon/kernel compatibility remains
a target-run requirement.

## Revised implementation

```text
committed RAM/rootfs lowers -> owner publishes SDK NC objects
 -> each node's isolated read-only broker imports once
 -> UbLayerFile -> existing tar/ZFile/LSMT -> each node's ublk
 -> existing FC File RAM CoW / independent rootfs writable upper
```

Memory and rootfs opt in separately. No setting means the original path, without
loading an SDK library. The broker calls only the installed public SDK through a
small C++ bridge compiled against its headers. Keeping mapped access in a separate
process isolates synchronous mapping faults from the ublk daemon; a Rust `Result`
is not claimed to catch SIGBUS.

An acquire connection binds object, generation, stored digest, effective length
and complete mapping size. It holds a reader reference until disconnect; reads
are bounded and never return partial-success data. Ready publication follows full
stored-byte verification and removal of the owner's writable mapping. Ancestor
objects can be borrowed without allocation or deletion ownership.

The runtime config is a new immutable, generation-specific view. Original cached
configs/catalogs stay unchanged, and the shared-device key cannot silently select
an old incarnation after an index update. For required UB, a node need not hold a
duplicate local lower file. An explicit repository fallback uses a pinned local
file whose complete digest/size matches; it rereads an entire failed range and
reports degradation. Remote-registry fallback is not silently substituted.

Retirement requires local read leases to finish and operator confirmation that
remote consumers have stopped. SDK busy/error leaves a receipt unresolved; there
is no TTL-only deletion, forced removal or global cleanup. A process restart does
not make an uncertain creation safe to replace with another random object.

The original design's centralized cluster-Fork/coordinator, PMEM/DAX and physical
Guest Base uniqueness are not properties of this first data-source integration.
They remain separate work. The supported initial deployment is two explicitly
targeted independent Runtimes; local page caches and IPC copies still exist.

## Experiments and acceptance

| Experiment | Success / failure criteria | Side effects and cleanup |
|---|---|---|
| Wire/state tests | Correct identity/range/EOF, chunking, errors instead of short success, no release during a live read. Any violation fails. | Local test sockets/files and an in-memory SDK double only; close and remove test-owned paths. |
| SDK smoke | One small NC object, readonly A/B imports, identical complete stored bytes, B allocation count zero, SDK unmap/finalize and owner deletion acknowledged. Any nonzero/timeout/data mismatch fails. | One 4MiB logical request, physical rounding unknown before creation; preserve uncertain identities, never force-delete. |
| Real layer formats | LocalFile and UB produce identical logical data for plain/tar/ZFile layers; independent writable uppers preserve base/sibling data. Parse differences or shared writes fail. | Test-owned layer files and fake broker locally; real SDK variant separately on target. |
| Failure/lifetime | Broker loss yields explicit I/O error or complete same-content fallback; a failed child does not delete successful siblings or a parent. | Stop only test brokers/VMs; leave unresolved SDK receipts for reconciliation. |
| A/B Guest acceptance | Same committed snapshot restores RAM and rootfs markers; divergent writes stay private; recapture preserves changes and reuses ancestor objects; disabling UB preserves original behavior. | Requires deployed baseline and modified binaries, isolated test objects, explicit resource budget and scoped cleanup. |

Acceptance is reported independently for RAM layers, rootfs lowers, formats,
Guest CoW, multi-generation references, cleanup/failures, opt-out regression and
repository delivery. Local tests and ARM64 cross-checks are not target executions.
No net memory saving or cluster-wide physical-page uniqueness is inferred from
backing coverage or cross-host PSS.
