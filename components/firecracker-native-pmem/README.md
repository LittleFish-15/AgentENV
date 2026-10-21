# Firecracker NC device-FD pmem backend

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
ARM64 GNU target. It preserves the pinned ARM64 musl policy and adds only these
VMM rules for GNU libc thread signalling and thread join:

- `getpid`;
- `tgkill`, restricted to signal argument 2 equal to 34;
- `futex`, restricted to operation argument 1 equal to 265
  (`FUTEX_WAIT_BITSET | FUTEX_CLOCK_REALTIME`) and argument 5 equal to
  `FUTEX_BITSET_MATCH_ANY`.

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

Snapshot save and restore reject native pmem before device-state mutation.
Serializing an inherited FD would not make it durable. This patch requires the
matching AgentENV consumer, provider, verifier and new Guest tools image. Its
parser/unit checks do not establish KVM mapping, Guest DAX or cross-node sharing.

`native_fd.rs` is the canonical source shared by the verifier. The patch embeds
the same file for the separate FC checkout; its normalized SHA256 is pinned in
`baseline.json`. Do not edit either copy without regenerating the patch.
The process FD limit must leave room above FD 512 for private source duplicates;
insufficient limits fail without changing host settings.
