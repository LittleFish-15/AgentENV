# Native shared backing: experimental FD and pmem/DAX consumer

This is a separate, **disabled-by-default** path toward shared physical RAM and
shared read-only file data. It does not turn the existing UB layer broker into a
native FD provider. It does not claim UB/KVM/DAX hardware validation or memory savings.

## Implemented

- `AENV_DIRECT_MEMORY_BINDING=/absolute/binding.json`: restore a matching snapshot
  from a full linear backing received by SCM_RIGHTS, bypassing the memory ublk.
  Ordered committed lower digests/lengths and logical RAM length bind the selection.
  Wrong images, absent identities, unsupported providers and unsupported CoW fail;
  there is no silent local-copy fallback. ublk is still needed for ordinary disks.
- `AENV_DIRECT_ROOTFS_BINDING=/absolute/binding.json`: experimental **cold boot**
  with 1..8 read-only pmem EROFS layers and a private writable ext4 `/dev/vdb`.
  The requested source image identity must match. The existing disk supplies only
  the private overlay directory; this tool does not create/format a blank disk.
- Child-private FD inheritance uses reserved descriptors 10..17 for pmem and 18
  for RAM. Parent descriptors stay CLOEXEC and are not globally reassigned.
  FC opens `/proc/self/fd/N` **inside its own process**, avoiding parent `/proc`
  access and without changing FC's public API. Leases remain held through FC use.
- The provider must return read-only, seekable, readable, mmap-compatible FDs
  covering exactly the declared image from offset zero. Full SHA verification
  uses positional reads, because SCM_RIGHTS descriptors can share a file cursor.
- UB sources must be cacheable (`cacheMode=cc`). NC/O_SYNC FDs are refused:
  FC's path reopen would lose O_SYNC and could change the OBMM mapping attributes.
- The new tools image checks STATX_ATTR_DAX on every non-empty regular lower file
  (bounded to 100,000 tree entries), and on a probe through the final OverlayFS
  root. aenv checks the final probe after envd becomes ready. No DAX means failure,
  not a successful ordinary-cache fallback. The probe must exist in each image.
- Cold pmem **pause/capture/Fork and restore are intentionally refused** before
  pausing the VM. Durable pmem object references, rebuilding, and coordinated
  release across snapshot lifetimes are not implemented. Existing snapshots and
  the ordinary mode keep their old behavior.

No change to host ACLs, devices, capabilities, networking, SDK installation,
existing services, or BIOS is performed by these tools.

## Native provider wire contract, version 1

Unix stream socket; same UID as aenv, private directory, socket mode 0600.
Both JSON messages use a four-byte big-endian byte length, then UTF-8 JSON, at most
4096 bytes. aenv sends:

```json
{"version":1,"operation":"acquire","objectId":"base","generation":"v1","sha256":"sha256:...","bytes":2097152,"privateCow":false}
```

The provider replies with:

```json
{"version":1,"state":"ready","backing":{"objectId":"base","generation":"v1","sha256":"sha256:...","bytes":2097152,"socket":"/run/user/1000/native/provider.sock"},"privateCow":false,"source":"ub","cacheMode":"cc"}
```

It then sends exactly one FD using SCM_RIGHTS with a single byte `F`. The backing
must remain immutable and pinned until the connection closes **and all handed-off
FDs/mappings are no longer used**. `privateCow=true` is required for RAM and must
describe the real kernel/KVM contract, not only SDK MAP_SHARED support. IDs are
portable; FD numbers and the socket path are node-local and must not be copied
across nodes as resource handles. No raw FD numbers appear in persistent snapshots.

This consumer supports one linear FD per object. Segmented UB allocations and
mmap-only/non-seekable character FDs are **not** supported by this FC File API
path. They require a range-aware/FD-aware FC backend or a supported platform view.
Never substitute memfd copies and call that native cross-node UB sharing.

## UB source review

Reviewed `openeuler/ubs-mem` at
`dd7de593843bdc1e9ef4c4660bc86ff3ec499219`:

- Public `ubsmem_shmem_allocate` returns a status and `ubsmem_shmem_map` returns an
  address. The SDK's own mapping opens backing devices per memory ID and stitches
  the mappings, rather than returning one logical-image FD.
- `src/app_lib/common/rack_mem_libobmm.h` constructs `/dev/obmm_shmdev<id>`;
  `rack_mem_lib_common.h::ObmmOpenInternal` selects O_SYNC for noncache modes.
- `RackMemShm.cpp::RackMemShmMmapByMemID` opens one FD per backing unit.
  Public map documentation specifies MAP_SHARED. This is not a guarantee that
  the raw device supports file-private RAM CoW, seek, read, or KVM page acquisition.
- `ubs_mem_fd_get` in UBSE is a borrowing/debt query, not an interchangeable
  public export of the named shared object used by this project.

This establishes that UB has an FD layer, **not** that the current installed
version exports a single FC-compatible shared FD. Do not scrape SDK private FD
tables or switch to exclusive borrowing and report cross-node sharing.

## Preparation and mechanism checks

1. Export the **logical RAM view**, not its stored layers:

   ```sh
   cargo run --locked -p overlaybd --example export_native_memory -- GLOBAL_JSON MEMORY_IMAGE_JSON /absolute/new-memory.raw MAX_BYTES
   ```

   This streams the entire image with bounded buffers, preserves zero-page file
   holes, and reports actual file allocation when available. Incomplete output is
   retained on failure. The output must be new. Export, publication, hashing and
   imports are preparation costs, not cold-cache measurements.

2. Prepare a binding in a new directory. `--max-bytes` is an explicit input/address
   range budget, not a physical UB quota:

   ```sh
   python3 -I -B tools/native-backing/native_backing.py prepare memory --source MEMORY_IMAGE_JSON --image /absolute/new-memory.raw --socket /absolute/private/provider.sock --max-bytes MAX_BYTES --output /absolute/new-binding
   ```

   For rootfs, use `prepare rootfs`, pass each image with `--image` in bottom-to-top
   order, and give the matching committed source image config to `--source`.
   Images must be compact, uncompressed, DAX-capable EROFS, include a non-empty regular
   `/.aenv-dax-probe`, and have file lengths padded to 2MiB. This tool hashes and
   binds prebuilt images; it does **not** convert OCI/OverlayBD into EROFS or prove
   the filesystem contents were built faithfully. A trusted builder is still needed.

3. An optional Linux **local fixture** validates FD plumbing without UB:

   ```sh
   python3 -I -B tools/native-backing/native_backing.py fixture-server --catalog /absolute/new-binding/fixture-catalog.json --socket /absolute/private/provider.sock --max-bytes MAX_BYTES
   python3 -I -B tools/native-backing/native_backing.py probe --binding /absolute/new-binding/binding.json
   ```

   The fixture allocates sealed local memfd memory and reports
   `sealed_memfd_fixture`, never `ub`. Do not run it as root. It copies the source
   and therefore cannot establish UB savings. `probe --kvm` optionally registers
   and unregisters memory in a fresh VM; it creates no vCPU and runs no Guest.
   UB write-probing requires `--owned-test-object`, never a published production base.

4. Build a **new immutable tools release**, with the appropriate Guest kernel
   support. Never overwrite an installed tools version or restart a live Runtime
   as part of these commands. New startup code must be present for the pmem mode;
   aenv's readiness check rejects old tools that ignore the new boot argument.

5. `python3 -I -B tools/native-backing/preflight.py` collects a single read-only
   prerequisite report: public header signatures, UB feature bits and KVM access.
   It calls no SDK, allocates no object, runs no Guest and changes no permissions.
   Advertised bits are reference decoding, not hardware acceptance.

## Remaining acceptance

Real UB provider and cache ownership; segmented/raw FD compatibility; RAM CoW
under KVM; Guest EROFS/OverlayFS DAX on the target kernel; durable pmem snapshot
references and multi-generation restore; bounded shared-pool reclaim; and actual
global memory savings/task density. These require further implementation and/or
target evidence. DAX removes file-cache copies; read() buffers, parsed objects,
private dirty pages, page metadata and page tables remain costs.

Under a 4KiB-page/64-byte-page-metadata model, pmem metadata alone is approximately
1/64 of the exposed address range per Guest. Budget the compact exposed image,
not the original disk's large virtual capacity. Count the shared pool once and
include every real local allocation; do not sum complete page cache and Guest PSS.
