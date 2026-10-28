# Experimental OBMM Host pmem/DAX read-only frontend

This is an **unaccepted kernel candidate**, not a loadable release. It adds an
OBMM-owned readonly block/DAX read-iterator frontend, not System RAM, devdax,
Guest-pmem, memory hotplug or memfile private CoW. No install/load/unload helper
is provided here. Keep the current kernel and OBMM until native Kbuild/modpost,
review and a separately approved isolated deployment have succeeded.

## Source integration

The exact kernel source baseline is recorded in `baseline.json`. Apply
`obmm-integration.patch` to those matching files, and place `obmm_pmem_ro.c`,
`obmm_pmem_ro.h` and `obmm_pmem_uapi.h` under `drivers/ub/obmm/`. Build the entire
OBMM module against the matching configured kernel tree. Do not compile only
the new file and name it obmm.ko, use private-symbol lookup, or force vermagic.

With CONFIG_FS_DAX enabled the frontend is compiled into OBMM. Its new module
parameter `pmem_ro_enable` defaults to false and is read-only after load. The
control device is absent when disabled. Enabling it is a privileged deployment
operation, not a build step. The ordinary OBMM default creates no new volumes.

## Contract

- Control operations require CAP_SYS_ADMIN in the initial user namespace.
  CREATE accepts 1..32 opened readonly O_SYNC OBMM region FDs and aligned
  ranges. It verifies actual fops/region identity and never accepts bare PA.
- Only non-NUMA, pool-backed export or ordinary import regions with NC mapping
  capability are accepted. Export-user-address regions are outside v1.
- A volume is limited to 16GiB and 1024 physical extents. Export SG ordering is
  preserved; importer ranges retain their existing backing. Oversized or partial
  failures produce errors, not local payload copies.
- Each region receives an irreversible local seal after checking that no NC
  writable VMA remains and no conflicting CC mapping mode exists. Sealed regions
  reject future writable/executable or CC mappings. A failed group attach can
  leave earlier regions sealed; retire that generation, never implicitly unseal.
- Readonly SDK mappings may remain as control-plane anchors. Kernel views keep
  O_SYNC mapping mode selected even when the last user VMA closes.
- Export pages use a readonly NC vmap; import ranges use readonly NC ioremap.
  No new dev_pagemap, normal-RAM conversion or buddy allocation is performed.
- The frontend exposes a readonly whole-disk device with DAX registration.
  Block reads serve filesystem metadata; modifying BIO operations are rejected.
  DAX direct_access supplies stable kernel addresses only for read_iter calls
  with pfn == NULL. It never fabricates PFN_MAP/devmap page metadata.
- File mmap is outside the supported contract. A read fault requesting a PFN
  fails; this does not mean every mmap syscall is rejected at entry, or that
  private-CoW/hole paths cannot produce local anonymous pages. Consumers must
  explicitly use read_iter mode; do not execute files from this Host mount.
- No power-loss persistence or MAP_SYNC is claimed. Prepare and validate an
  immutable image, complete required UB publication ordering, then seal.

## Lifetime

Volumes persist independently of the creating process and pin the OBMM module
and every referenced region. A duplicate CREATE UUID returns EEXIST; resolve a
lost response by STATUS of the same UUID instead of allocating a replacement.
STATUS reports the local device, opener and active-I/O counts and read counters.
Its DAX span counter measures offered spans, not bytes consumed or residency.

DESTROY requires both UUID and the observed local volume ID. It refuses any
block opener, including a mounted filesystem. It closes admission, removes the
disk/DAX association, waits for DAX SRCU and ordinary BIO completion, unmaps, and
then releases local region references. A local destroy is not a peer-release
acknowledgment and must never directly authorize UB deallocation.

Keep the owner's anchor until every peer has a confirmed exit receipt. SDK
unmap may initiate detach, so perform it only after local DAX retirement. Owner
or importer process death, timeout or lost reply does not authorize reclaim.
Kernel references preserve local region storage against ordinary OBMM removal;
fabric/control-plane failure behavior still requires target-version validation.
Unknown references and partial failures remain explicit reconciliation work.

## Host reader

The userspace control implementation is in
`../ub-memory-provider/aenv_ub_provider/host_pmem.py`. It encodes CREATE/STATUS/
DESTROY from this UAPI, durably records intent through the caller's journal,
never retries CREATE, and checks the observed UUID/device/id before retirement.
An interrupted destroy is reconciled by STATUS, not a second blind destroy.
`tests/uapi_layout.c` checks all three ioctl numbers and the C layouts against
the target headers; Python tests check the actual encoded requests.

`host_pmem_lease.py` acquires the existing ordinary SDK provider's readonly
O_SYNC FDs. The privileged helper connects with the specified ordinary EUID in
a single-threaded bootstrap, restores root, and binds the peer UID/PID/start
time before receiving FDs. It does not load the SDK into root or relax the
provider's existing same-UID check. Its lease cannot be explicitly closed while
a volume may remain. SDK owners must continue running and must not be retired
merely because the privileged helper's socket disconnected.

`host_pmem_mount.py` uses a new private mount namespace and mounts only the
observed block device as `ext4,ro,noload,dax=always,nodev,nosuid,noexec`. It checks
mountinfo identity and options, and never uses forced/lazy unmount. The
`MountedSession` composition in `host_pmem_session.py` requires an already
running, exactly identified SDK owner; it connects the lease, volume, mount and
bounded pread verification. It persists the node boot and transaction before
resource changes. Explicit retirement orders unmount, volume absence, then
lease close. There is no automatic SDK deallocation or driver restoration.

File verification checks the exact local block device, active S_DAX, readonly
mount, expected length/digest, a positive DAX counter delta and EROFS on a
non-writing writable-open attempt. Failure does not fall back to a normal file.
These are local read-path checks, not two-node physical-identity or net-saving
evidence. The coordinator still has to bind both nodes to the same SDK
publication, retain peer references and collect complete release receipts.
Neither the Python unit tests nor the C layout compilation run these Linux
namespace/credential/mount operations on the target.

`host_pmem_cli.py` provides `plan`, foreground `serve`, authenticated root
`verify` without release, and explicit `retire` modes. `plan` makes no SDK/kernel
changes. `serve` requires the exact
configuration digest, explicit view/mount approval, and an already enabled
candidate matching the configured kernel release and module srcversion. It
holds the mount/lease after validation while the peer is tested. A failed
validation keeps the local control loop available for explicit retirement;
it does not fall back or automatically free the source. A lost completion
reply does not repeat cleanup. An orphan helper is not silently adopted.

New minimal experiments must set `hostPmemReleaseReceipt` in the ordinary
provider configuration on BOTH nodes. This optional field only applies to
pmem mode and exactly one image; old configurations keep their existing
semantics. Retirement then requires a root-owned release receipt matching the
publication owner, complete manifest hash, SDK object name, source generation,
local SDK process identity and boot. The root helper exports it only after
mount absence, volume absence and lease closure. The publisher additionally
requires the existing importer release receipts. Thus root-helper death or
socket disconnection alone does not authorize SDK cleanup. Export root
receipts into a root-owned, ordinary-user-traversable directory; private
transaction journals remain private. The receipt is local-retirement evidence,
not a physical-sharing or data-validation result.

Explicit retirement can reconcile a failed CREATE by querying that same UUID.
If it exists and is attributable to our intent, its observed ID must pass the
normal retirement checks. An EEXIST collision is never adopted. An ENOENT reply
proves current local absence, not historical creation success; the release
receipt records that distinction without inventing a volume ID. A failure
before any CREATE intent uses a separate never-attempted outcome. Neither case
allows skipping the peer release policy.

The guarded publisher can additionally pin `hostPmemReaderEpochs` before SDK
allocation. Only then can it accept a root-issued terminal pre-import
cancellation for that exact peer maintenance epoch and manifest. This is
distinct from an importer unmap receipt: it states that no import was attempted,
and the coordinator must permanently disable that peer's start action for this
experiment. Unknown/attempted imports cannot be relabeled as cancellations.

Before mounting, the helper sets and verifies read-ahead zero on the newly
created pmem device only (BLKRASET/BLKRAGET). It does not change existing disks or
global cache policy. Local verification optionally uses FIEMAP and mincore of
the *ordinary block-device mapping* to separate test-file data blocks from
other cached blocks. It refuses to interpret a DAX mapping's mincore as ordinary
PageCache. Unsupported, sparse or ambiguous accounting returns unavailable,
never zero. This distinguishes data-cache avoidance from filesystem metadata
and incidental block cache; all remain separate from process and UB-pool costs.
Verification records a reader-process RSS/PSS observation while the first
payload buffer is live. Its logical buffer length is included for interpretation,
not added again to process memory. This is a sampled cost, not a peak or a full
allocation-to-retirement global memory measurement.

Still outside these library/CLI components: the reviewed two-node deployment
wrapper, immutable test-container preparation, SDK-owner startup using retained
adapter pins, module maintenance/restoration, global object-provenance evidence
and memory accounting. Do not issue field commands until those pieces are
bound to one approved experiment. The core CLI by itself is not that wrapper.

Use the existing stored lower protocol with the new explicit version2 catalog:
`{"version":2,"access":"read_iter","files":[...]}`. The provider still checks
active S_DAX, readonly mount, exact stored length and content identity. It calls
pread on that DAX FD without mmap or ordinary-file fallback. Version1 retains
the previous mmap behavior and is incompatible with this restricted frontend.
The Host ext4 container holds the existing stored lower files; it is not the
Guest's filesystem image. Private Guest upper and ordinary Guest RAM are unchanged.

This avoids the selected lower's ordinary Host data PageCache in the intended
DAX read path. Filesystem metadata, kernel page tables, transient I/O buffers,
Guest caches, and private upper memory remain and must be measured separately.
Uncontrolled raw block reads or alternate users of old local files are outside
that guarantee. Freeze DAX inode/mount configuration during measurement.

## Rootfs consumer integration

`aenv_ub_provider.host_pmem_rootfs` composes the existing mounted UB image with
`host_dax_worker`. The root owner opens bounded direct-child lower filenames
with readonly, no-follow descriptors and validates their actual DAX device.
It passes those descriptors and a private socketpair to a child running under
the configured ordinary UID/GID with cleared supplemental groups. The child
does not reopen privileged paths, mmap the files, allocate UB or load SDK
libraries. It validates S_DAX/readonly/length/device and hashes each stored
lower before exposing the existing OverlayBD broker protocol. Header/padding
are protocol bytes, not extra UB allocations or file payload caches.

The root service must have the explicitly reviewed SETUID/SETGID capabilities
needed to launch this child, in addition to its existing mount permissions.
Never compensate for a denied spawn by running the consumer as root. The
inherited socket authenticates the exact root parent PID; the public broker
accepts only its ordinary UID. It defaults to two concurrent payload responses
while keeping reader leases independent of response-buffer slots.

The runtime index is published in a separate root-owned, ordinary-readable
directory only after the child validates every lower. First publication never
overwrites an existing index. Retirement refuses live readers, waits for child
exit, invalidates the owned runtime index, closes parent file references, then
unmounts/destroys the local view and exports the original SDK retirement guard.
An unconfirmed child exit cannot silently release the mount. A lost retirement
acknowledgment can be explicitly reconciled only after the same child exits
successfully following recorded retirement intent. Cross-node owner release
still requires the peer's actual receipt. The SDK image, manifest and ordinary
file source remain externally managed.

This rootfs control CLI is not a four-Guest experiment runner. Native child
credential/namespace/DAX validation and the exact Runtime deployment must be
accepted on the target before claiming real Guest lower access. Local tests
mock S_DAX and privileged operations; they do not prove a hardware data path.

## Validation limits

The Windows-side checks compile AArch64 translation units against matched
development headers and link a relocatable combined OBMM object. They do not
run Linux Kbuild/modpost, generate module versions/signatures, or create an
installable module. The host harness executes verbatim extracted production
read methods with model types; it is not a kernel concurrency or UB test.

Still required before enabling: native Kbuild/modpost and vermagic/dependency
inspection; lifecycle/seal concurrency review; isolated real NC bulk reads and
Host DAX mount; busy teardown and partial-failure behavior; controlled two-node
identity/isolation/cache accounting. Do not claim savings from compilation.
