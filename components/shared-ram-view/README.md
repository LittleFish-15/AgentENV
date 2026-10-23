# Normal-page private view core (experimental, not a UB RAM demo)

This GPL kernel component implements a private mapping over an immutable set
of normal pages supplied by a trusted kernel provider. It is **not** a complete
cross-node Guest RAM implementation. There is currently no OBMM provider,
userspace control device, Firecracker integration or hardware acceptance for
this component. Loading it does not create a base, allocate UB memory, change
memory topology or expose a raw-physical-memory interface.

## Intended mapping path

The provider transfers one owned reference per independent normal page into
`aenv_ram_base_create()`. It must keep the physical backing immutable and
non-revocable, with a valid, compatible kernel linear alias. The API rejects
device-zone, reserved, offline, compound, anonymous, already mapped, pinned,
dirty or page-cache pages. On ARM64 it also requires normal map-memory PFNs.
These checks do not prove cross-node visibility or UB provenance.

`aenv_ram_base_open()` returns an anonymous read-only backing file:

- A private read fault returns the existing base page, without making a
  per-view copy. The normal Linux private-file fault path performs write CoW.
- Writable shared mappings are not supported; all `MAP_SHARED` mappings are
  rejected. File writes and truncation are not provided.
- `pread` and `llseek` refer to the immutable base. They are not reads of a
  particular view's private modifications.
- Length comes from `aenv_ram_base_bytes()`. Anonymous inode `st_size` is not
  an object length and must not be modified: the inode is shared by the kernel.
- The provider must pass the open file/FD directly. Reopening a proc path is
  not part of the contract.
- Use a normal writable KVM RAM slot over the private VMA. The design does not
  use a readonly KVM slot and MMIO instruction emulation to handle RAM writes.

FD and VMA references keep the view open. Explicit owner retirement closes
admission and refuses to release while views, mappings or extra page references
remain. A busy retirement leaves existing views usable; it does not time out or
force reclaim. The provider must serialize owner API calls, keep its handle
until successful retirement and never use it after success. The local release
callback does not acknowledge peer release or remote object deletion.

## Provider work still required

Current OBMM device-mapping pages do **not** automatically meet this API. A
bridge must establish real base ownership, normal independent page metadata,
supported cache attributes, a readable kernel alias, publication ordering and
physical lifetime. In particular, neither a PFN from an OBMM query nor remote
NUMA pre-online metadata is sufficient. This component must not be connected
by casting OBMM private structures, changing device page attributes, using
unexported-symbol hooks or treating a local copy as shared UB RAM.

There is no fallback that makes an arbitrary input mapping appear supported.
The absence of a valid UB provider remains a missing implementation, not a
successful capability check.

## Build and acceptance status

The translation unit has been cross-compiled as an AArch64 freestanding ELF
object against matching openEuler 6.6 development headers. Its external symbol
names were checked against that package's `Module.symvers`. Clang's static
analyzer reported no diagnostics for this translation unit. These checks do not
replace a complete Linux Kbuild/modpost/module-signing build, kernel runtime
tests, GUP/DMA race tests or KVM execution. No module has been loaded.

The Makefile is an ordinary out-of-tree Kbuild fragment. There is intentionally
no install/load/unload script. Preserve the existing kernel and OBMM until a
complete provider, build, review and isolated test establish a deployable path.

A real cross-node demo must additionally demonstrate all three conditions:

1. Two nodes' Guest read mappings refer to the same UB owner/generation and
   backing offsets, with physical mapping evidence; matching hashes alone do
   not prove shared physical content.
2. A Guest write creates its own private page while the peer and base remain
   unchanged. A normal-page local control does not satisfy the cross-node gate.
3. Guest instruction fetch, page-table accesses and host/device-side writes
   work through the same mapping contract.

Until these are established, report cross-node RAM CoW and savings as
unaccepted. This component's metadata, provider and UB physical costs must be
included in any eventual memory comparison.
