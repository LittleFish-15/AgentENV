# Stored-byte demand pool for rootfs lower

This opt-in branch retains the rootfs path `Runtime -> ublk -> OverlayBD ->
UbLayerFile -> local broker`. It neither replaces the full-object deployment
nor maps UB into Guest RAM. Memory snapshots and private upper remain on their
existing paths.

The Runtime requires both the node index SHA256 and a separate demand manifest
SHA256. Cold start and POSIX snapshot restore validate the manifest's cache
generation, one bounded pool, 64 KiB stored-byte catalog and every selected
virtual lower before returning a usable runtime configuration. A virtual
layer's mapping length is a wire descriptor, not a separate physical object.
Only `manifest.pool` is allocated by the demand provider.

The catalog covers original stored bytes, including OverlayBD/ZFile headers,
compressed records and indexes. The existing format reader decompresses these
bytes normally; 64 KiB chunks are not Guest pages or independently decompressible
ZFile blocks. Catalog generation scans each complete source with O_DIRECT and
checks its committed digest. This preprocessing is not demand filling: it
produces hashes but fills no UB payload. Both preprocessing and subsequent
owner misses reject direct-I/O failure instead of falling back to buffered
source reads. Importers have no source-file payload reader.
Direct source buffers use the supported host page size (4, 16 or 64 KiB),
including the short final chunk, matching the full-mode DirectFile policy.
This is an alignment contract, not evidence that a particular target filesystem
accepts O_DIRECT; the native scratch-file test and actual source preparation
must still pass without a buffered fallback.

The existing coordinator admits one loader per `(layer digest, chunk index)`.
It verifies source bytes, writes the shared slot and verifies readback before
publishing READY. Readers hold durable pins while reading shared slots and
verify the chunk digest. A lost grant or release leaves a conservative pin;
disconnect does not reclaim unknown references. Eviction excludes pinned or
loading slots. Cache generation, lease identity and content hash guard reuse.
When every slot is temporarily pinned or loading, the actual acquire path
waits on the same condition as coalesced fills. Both waits share the original
30-second request deadline; spurious wakeups do not renew it. Pin release,
fill completion or admission closure causes ownership to be rechecked before
any slot can be reused. Capacity timeout fails without evicting a live pin,
reading a local fallback, or extending Guest/CLI deadlines. This prevents a
short capacity contention from immediately poisoning an otherwise healthy
Reader. `capacityWaits` is a subset of `waits`, not an additional total.

Counters include hits, misses, waits, waitNs, evictions, backendBytes,
firstFills, refills, successfulFills and fillErrors. The historical filled-key
set is bounded by the validated catalog limit of 200000 chunks and contributes
to provider metadata overhead. Count the entire actual pool allocation and its
SDK backing coverage even when readyBytes is small. Requested poolBytes,
backing coverage, readyBytes and incremental physical cost are distinct values.

Owner retirement must also confirm the metadata accept thread has exited after
its bounded join, as well as confirm that no metadata worker remains. A join
timeout preserves the socket identity and causes retirement to stop before SDK
unmap/deallocation. It is not evidence that an OS thread or shared pool exited.

Node status also includes the actual stored broker's activeLeases,
activePayloadResponses and payloadFailures. Payload activity spans the mapping
read through completion of the socket response; a mapping exception, short
read or lost response increments the failure count, never successful bytes.
These are node-local broker counters, distinct from coordinator chunk pins and
fillErrors. Zero active responses is not proof that reader leases or SDK
objects have been released. Status inspection does not release any resource.

Mapping exceptions or failed imported-chunk integrity checks close the reader
generation's admission, preserve the outstanding pin and durably record
readerFailed in owner.json. Other broker connections cannot implicitly recover
that reader by trying another block. An already active parallel read must not
publish success after observing this failed state. Ordinary retirement is
refused before any SDK unmap/finalize/delete when the local reader is failed;
explicit reconciliation is required. This conservative retention includes a
pin whose synchronous read failed, rather than claiming a healthy generation.

Status remains locally observable after failure. It does not retry coordinator
RPCs for a failed reader: local broker/reader counters remain available, while
unconfirmed coordinator pins/loading/readyBytes are null. The state is
unresolved_preserved and the status CLI returns nonzero. A healthy local
reader whose status RPC fails also closes admission; unavailable information
is never turned into zero pins or a successful retirement receipt.

The provider is executable through `python -m aenv_ub_provider.lazy_service
prepare ...` and `serve config --run`; preparation and serve retain separate
commands and fresh output/state directories. The importer still requires an
authorized transport reaching the owner's metadata coordinator socket. This
branch does not create a cross-node tunnel, open a network port or assume SSH
permission. Such deployment remains a gate, as does native UB concurrent
visibility and two-node real Guest acceptance.

Local checks cover production Rust configuration/protocol code, ARM64 Runtime
and daemon compile checks, provider concurrency/lifecycle contracts and
direct-catalog error behavior. They do not establish Linux filesystem O_DIRECT
support, hardware coherence, Guest correctness or net memory savings.
