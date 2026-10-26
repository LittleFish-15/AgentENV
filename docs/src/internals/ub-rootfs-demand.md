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

The existing coordinator admits one loader per `(layer digest, chunk index)`.
It verifies source bytes, writes the shared slot and verifies readback before
publishing READY. Readers hold durable pins while reading shared slots and
verify the chunk digest. A lost grant or release leaves a conservative pin;
disconnect does not reclaim unknown references. Eviction excludes pinned or
loading slots. Cache generation, lease identity and content hash guard reuse.

Counters include hits, misses, waits, waitNs, evictions, backendBytes,
firstFills, refills, successfulFills and fillErrors. The historical filled-key
set is bounded by the validated catalog limit of 200000 chunks and contributes
to provider metadata overhead. Count the entire actual pool allocation and its
SDK backing coverage even when readyBytes is small. Requested poolBytes,
backing coverage, readyBytes and incremental physical cost are distinct values.

Node status also includes the actual stored broker's activeLeases,
activePayloadResponses and payloadFailures. Payload activity spans the mapping
read through completion of the socket response; a mapping exception, short
read or lost response increments the failure count, never successful bytes.
These are node-local broker counters, distinct from coordinator chunk pins and
fillErrors. Zero active responses is not proof that reader leases or SDK
objects have been released. Status inspection does not release any resource.

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
