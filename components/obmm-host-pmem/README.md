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
