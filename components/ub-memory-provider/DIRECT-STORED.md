# Direct UB stored lowers (independent experimental branch)

Use `mode: "stored-direct"` with the existing `aenv-ub-provider serve` publisher
and importer configuration schema. Set `sourceRoot` and `images` to the selected
ordinary rootfs stored-layer inventory, not memory or native-pmem bindings.
`AENV_UB_ROOTFS_REPLICAS` points to the generated node-local runtime-index.json.
Do not set `AENV_DIRECT_ROOTFS_BINDING` or memory UB settings for this experiment.

The new mode performs complete O_DIRECT source validation before SDK allocation,
then publishes from the same pinned FDs, checking identity before and after each
read. Linux page-aligned anonymous scratch buffers support bounded EOF tails;
unsupported direct IO fails without buffered fallback. Publication rejects reuse
and local repository fallback. Historical resident source pages are not evicted.

The existing NC SDK adapter and wire protocol are unchanged. The broker limits
live payload responses to two, including blocked sends; idle Guest leases do not
reserve payload capacity. Its status control request is `{"operation":"status"}`.
The limit is not a bound on all socket buffers, Python allocator arenas or daemon
memory. Every configured remote reader must still release before owner retirement.
Unknown receipts or failed generations must be reconciled, not recreated.

This is application-specific shared stored content, not Host FS-DAX, Guest
physical-page sharing, memfile CoW or kernel-enforced sealing. SDK PROT_READ
protects each reader mapping. A controlled publisher must stop writing before
publication; the existing adapter fence alone is not proof of fabric-wide drain.
Peer verification and platform semantics remain target acceptance requirements.

Read-path review at parent ecd5b21:

- image_file.rs required UB skips local-file opening and download. UB reads pass
  through UbLayerFile and the local broker; fallback=false is mandatory.
- ZFileRO retains its header/jump table/compressor/metrics rather than a block LRU.
  Compression scratch buffers have a per-thread free list limited to four buffers,
  each at most twice MAX_COALESCED_READ_SIZE. Count them as process overhead.
- Premerged LSMT index caching remains. It is metadata, not proof of zero Host
  cache. Prefetch and kernel/ublk/Guest caches must be measured separately.
- Upper writes remain on the existing private storage path.

Validation: portable tests exercise real broker coordination and modeled source
FD/direct-read contracts. test_direct.NativeDirectIO is Linux-only and must pass
with the actual target filesystem before SDK publication. None of these tests
attests two-node hardware identity, Guest completion or physical net savings.

Experiment stages: (1) pinned native preparation/inventory, (2) source budget and
matching runtime deployment, (3) Host object/export-import proof, (4) one Guest
per node, upper isolation and A-exits/B-still-reads, (5) explicit release and paired
accounting. No four-template rollout until this closes. Full-object UB allocation
may exceed the working set and produce negative savings. Do not substitute SDK
mapping coverage for unique physical cost; unknown net savings must remain null.

Original pmem branch/worktree and kernel module artifacts remain unchanged.

Direct mode also writes `mapping-evidence.json`: public SDK readonly segment
lookup is tied to each object name, logical offset, length and local OBMM device.
Importer allocationCalls must be zero. This is provenance for subsequent
readonly VMA/OBMM-region observation, not automatic physical-sharing acceptance.
No physical addresses, private SDK descriptors or kernel changes are used.
