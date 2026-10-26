# Host FS-DAX stored lower reader (conditional backend)

Scope: share immutable **Host lower-file data**, while retaining the ordinary
Guest block-I/O and Guest RAM path. This does not use FC virtio-pmem or Guest
DAX. It does not need KVM to map or execute UB memory. memfile sharing is outside
this backend. The earlier Guest-pmem FS-DAX provider is a different consumer.

The intended chain is an existing supported shared UB publication -> Host
pmem/readonly FS-DAX filesystem -> `aenv_ub_provider.host_dax` -> existing
OverlayBD stored-layer broker protocol -> ublk -> ordinary Guest block I/O.
**The UB-to-pmem presenter is not implemented here.** Do not label a raw NC FD,
ordinary file, sparse file, tmpfs, or loop device as that presenter.

## Reader implementation

Each source is an already published immutable stored OverlayBD layer file on an
existing readonly FS-DAX mount. Before reading contents, the reader checks the
open FD's type, exact length, active S_DAX attribute and readonly mount. It then
maps the file readonly, verifies its full stored SHA256 in bounded reads, and
serves ranges through the existing broker. Ordinary files are rejected before
mapping/hashing. There is no data refill cache, file download, local payload
copy retained by this adapter, or repository fallback.

The wire header is synthesized from the catalog; payload bytes come directly
from the DAX file. `mappingBytes` retains the legacy wire's 4MiB-rounded logical
length including a virtual 4KiB header. It is **not** a physical UB allocation,
file length, DAX extent size, or measurement. Generation and digest matching are
protocol checks, not independent evidence of cross-host physical identity.

Use only a catalog whose UB provenance and generation retention have been
established separately. DAX on local pmem would satisfy S_DAX but would not
establish cross-node sharing. The readiness receipt always leaves physical
identity acceptance false for the experiment to establish independently.

Catalog schema:

```json
{
  "version": 1,
  "files": [{
    "path": "/readonly-shared-dax/layer.commit",
    "replica": {
      "brokerSocket": "/run/user/1000/dax-lowers.sock",
      "objectName": "aenv_11111111111111111111111111111111",
      "generation": "22222222222222222222222222222222",
      "layerDigest": "sha256:<64 lowercase hex digits>",
      "fileBytes": 8192,
      "mappingBytes": 4194304,
      "allowRepositoryFallback": false
    }
  }]
}
```

The following is conditional usage documentation, not a target deployment step:

```sh
python3 -m aenv_ub_provider.host_dax --catalog catalog.json --runtime-index fresh-index.json
```

Version1 catalogs use mmap as above. A version2 catalog must additionally set
`"access":"read_iter"`; it explicitly uses pread on the verified S_DAX file,
revalidating the FD before each payload read. There is no automatic switch from
failed mmap to pread and no short-read fallback. This mode is intended for the
experimental OBMM readonly DAX read-iterator frontend. That frontend must be
implemented, built and accepted separately; S_DAX alone is not UB provenance.

The foreground service emits the existing stored-layer runtime index only after
all source files are validated and the socket is listening. Bind it only to
rootfs through the existing explicit rootfs-replica configuration. Do not enable
the native Guest-pmem or memory-replica configuration for this experiment. The
`ub` source label in the legacy consumer protocol is not a hardware attestation.

## Lifetime and accounting

Local connections retain the mapped sources. A requested stop refuses active
reader leases and keeps serving; after consumers disconnect, request stop again.
The last broker response is released before waiting on an idle connection.
Unmapping local files never authorizes freeing the shared UB publication. The
external publication owner must retain the physical region and its immutable
contents until consumers on **all** nodes have exited, including abnormal-exit
reconciliation. No TTL, lost response, or empty local inventory proves remote
release. This adapter never frees UB, formats a filesystem, remounts a volume,
loads a module or changes a kernel.

Bounded request buffers and socket buffers are still local copies during I/O.
Guest file caches, private upper data, filesystem/layer indexes, and service
overhead remain. There is no claim of zero memory consumption or zero copying.
Full publication hashing touches DAX contents and must be separated from the
measurement window; it does not establish hardware residency or net savings.
Background users can still populate unrelated/local file caches, so the precise
invariant is no buffered read/fallback of the selected lower files by this path.

Snapshot export that materializes ancestor files is outside this first demo;
do not trigger it and then claim all Host lower data stays exclusively in UB.
Existing durable artifacts and the platform publication remain external inputs.

## Validation boundary

Local tests exercise the actual adapter and stored broker protocol, with S_DAX
and Unix open flags modelled on non-Linux hosts. They cover fail-before-read,
identity mismatch, range boundaries, partial-open cleanup, active lease stop
refusal, exact wire bytes and idle response-buffer release. These are not
pmem/UB hardware acceptance or proof that the full ublk chain creates no cache.

Two-node acceptance still requires an actual supported shared DAX presenter,
matching physical object/range evidence, end-to-end cache accounting and tests
of private writes, peer survival and failure cleanup.
