# Firecracker NC, FS-DAX and ordinary Host-file pmem backends

The ordinary Host-file backend is the DSec-style page-cache sharing path. It
requires neither Host FS-DAX nor physical persistent-memory hardware. Version 5
is `aenv-pmem-fd:v5:SHA256_HEX:BYTES:hostfile:FD`; it validates an exact readonly
regular file with inactive Host S_DAX and maps it shared/readonly. It uses the
same content-only snapshot references and fresh-FD restore checks as v3/v4.
This shares Host file pages among local Guests, not RAM across nodes. See
[Host page-cache provider](../ub-memory-provider/HOST-PAGECACHE.md) for the
matching Runtime v5 binding, provider protocol and immutability contract.

Apply `native-pmem-fd-v2.patch` only in an isolated checkout whose input
files match `baseline.json`. Hashes refer to the LF-normalized reviewed source;
they do not attest any installed binary or infer an upstream release tag.
Run `git apply --check`, apply, and build the complete FC using its unchanged
Cargo.lock. Record the resulting binary SHA256 in the AgentENV rootfs binding.

The segmented path is `aenv-pmem-fd:v2:TOTAL:nc:FD@BYTES,FD@BYTES` with 1..32
segments, positive 2MiB-aligned lengths and an exact sum. Each of up to 8 devices
uses a separate ordered FD group in 64..319. FC duplicates every readonly
`O_SYNC` character FD, reserves an inaccessible aligned address range and replaces
only its own reservation with the readonly/shared segments. Partial failures
unmap the owned range. No unrelated address is replaced. Segment VMAs retain
their file references; a separate inherited socket pins the provider generation.
The legacy single-FD v1 descriptor remains readable. Ordinary file-backed
pmem keeps its original behavior. There is no seek, pread, path reopen, SDK call,
local memfd substitution or disabling of seccomp in this backend.

The patch includes `resources/seccomp/aarch64-unknown-linux-gnu.json` for the
ARM64 GNU target. GNU adds these VMM rules for libc thread signalling and join:

- `getpid`;
- `tgkill`, restricted to signal argument 2 equal to 34;
- `futex`, restricted to operation argument 1 equal to 265
  (`FUTEX_WAIT_BITSET | FUTEX_CLOCK_REALTIME`) and argument 5 equal to
  `FUTEX_BITSET_MATCH_ANY`.

Both ARM64 GNU and musl additionally allow `statx` on FD >= 512 with exactly
`AT_EMPTY_PATH` and `STATX_BASIC_STATS`, and `fstatfs` on FD >= 512. These check
active FS-DAX and the readonly mount of duplicated inherited files. They do not
permit new writes, change vCPU policy, or disable filtering. FS-DAX support on
other architectures requires a corresponding reviewed policy before use.

Default actions remain `trap`. API and vCPU thread policies are unchanged.
The GNU resource is embedded by the normal FC build for that target, including
debug builds. A missing resource fails the ARM64 GNU build instead of selecting
the upstream empty fallback. Other targets keep their original build behavior.
Copying
the unmodified musl resource to the GNU filename is insufficient. The canonical
GNU policy is kept beside this README and its digest is in `baseline.json`.
The patch embeds an identical copy. Keep both copies in sync when updating the
reviewed FC baseline. These narrowly scoped rules do not establish compatibility
with arbitrary libc versions or additional FC features.

Applying the updated patch to a source tree with an existing GNU resource is
refused by `git apply`; inspect the existing resource and use a fresh reviewed
checkout. A previously built binary does not gain the embedded policy merely
because the patch or resource file was updated.

Version-1/2 descriptors still reject snapshot save/restore. Version 3 is
`aenv-pmem-fd:v3:SHA256_HEX:TOTAL:nc:FD@BYTES,...` and requires the matching
AgentENV version-3 binding. Saving replaces the process-local path with
`aenv-pmem-content:v1:SHA256_HEX:TOTAL`; no source FD or provider socket is saved.
Restore reads a private `aenv-pmem-restore.json` in the new FC launch directory,
with `{"version":1,"paths":["<fresh v3 descriptor>"]}`. The orchestrator must
first acquire new leases and verify the complete contents using the pinned
isolated verifier. Missing, duplicate, changed-content or changed-length
rebindings fail; raw inherited FD paths in old snapshots remain rejected.
The restored pmem mapping must also match the saved device address-range size.

By default immutable bases remain externally retained dependencies. The matching
Runtime can opt into `--retain-snapshot-bases` when preparing v3 bindings: exact
source images then become verified per-snapshot repository artifacts. Content
metadata alone does not keep an SDK allocation alive. After retirement, explicitly
republish retained bytes and bind the new generation; `bind-retained-snapshot`
prepares that catalog without making an SDK call. Old snapshots lacking archives
still require their external sources. Private writable OverlayFS state uses
the ordinary per-sandbox disk snapshot path. This is a coordinated Runtime/FC
implementation requiring native capture/restore/Fork testing; compilation and
protocol tests do not establish that hardware acceptance or memfile private CoW.

`native_fd.rs` is the canonical source shared by the verifier. The patch embeds
the same file for the separate FC checkout; its normalized SHA256 is pinned in
`baseline.json`. Do not edit either copy without regenerating the patch.
The process FD limit must leave room above FD 512 for private source duplicates;
insufficient limits fail without changing host settings.

## FS-DAX transport

Version 4 is `aenv-pmem-fd:v4:SHA256_HEX:BYTES:fsdax:FD`. It names one inherited
readonly regular file, not a character-device mapping. The shared parser accepts
4KiB multiples for the RAM verifier; the FC pmem device requires 2MiB multiples.
`statx(AT_EMPTY_PATH)` must report active S_DAX, exact length, and `fstatvfs` must
report a readonly mount. Ordinary files and raw device-DAX/NC FDs fail. Mapping
uses the existing shared readonly pmem VMA; private RAM uses the Runtime's
separate memory binding and standard private snapshot mapping.

Version-4 snapshots use the same portable content references as v3. New local
FDs and live provider leases are mandatory on restore. Do not serialize an old
FD, infer a physical UB identity from a content hash, or use a local-file copy as
a shared-base fallback. The isolated verifier performs the full hash and, for
RAM, two private-view first-write checks before FC starts. These checks establish
neither KVM execution support nor two-node physical sharing.

An existing supported UB-to-pmem/FS-DAX presenter is still required. This code
does not create that device, change OBMM/KVM, mount a shared filesystem writable,
or upgrade firmware. In particular, an ARM64 kernel may classify a DAX PFN as a
device and refuse Guest instruction fetch even though Host private CoW works.
The three Guest acceptance gates remain required before calling this shared RAM.
