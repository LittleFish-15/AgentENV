# Experimental FC device-FD pmem backend

This patch implements the first FC-side change required by the observed UB
device contract. It is **not** an end-to-end UB provider, KVM/DAX acceptance,
RAM CoW implementation, or deployable AgentENV release.

An owned disposable aarch64 target probe observed:

| Operation | Observation |
| --- | --- |
| Open a readonly NC device FD via public SDK lookup ID | Succeeded |
| MAP_SHARED, PROT_READ and two marker reads | Succeeded |
| lseek(SEEK_END) | ESPIPE (29) |
| pread | EINVAL (22) |
| Reopen /proc/self/fd/N | Open succeeded; O_SYNC was lost |
| MAP_PRIVATE, PROT_READ\|PROT_WRITE on the readonly FD | EINVAL (22) |
| Child exits and SDK unmap/delete/finalize | Confirmed successful |

Only this mapping combination and object were tested. EINVAL does not identify
the precise failing kernel branch or prove that every possible UB CoW design
is impossible. No KVM, vCPU, Guest, DAX, physical-increment or cross-node-native-FD
acceptance was performed.

## Change

The patched FC recognizes the explicit experimental form in `path_on_host`:

```text
aenv-pmem-fd:v1:10:4194304:nc
```

This is a descriptor request, not a filesystem path. FD must be 10..17, length
must be positive and 2MiB aligned, and the pmem configuration must be readonly.
The new backend duplicates the inherited FD with F_DUPFD_CLOEXEC, requires
O_RDONLY/O_SYNC and a character device, then uses a readonly MAP_SHARED mapping
of exactly the supplied length. It never reopens a path, reads/seeks the device,
allocates UB memory, changes caching mode or falls back to a local copy.

Malformed native requests fail. Ordinary paths retain the existing implementation.
The mapping and duplicate are owned by the existing Pmem lifecycle. Eventfds are
allocated before mapping so a later eventfd failure cannot leak a new mapping.

The existing string field carries this experimental versioned form to avoid
adding fields to the persisted PmemConfig/bitcode schema. **Native save and
restore are refused** before device save/restore work: process-local FD numbers
cannot be made durable by serializing them. Portable object identities, provider
retention, FD reacquisition and reconstruction are future work.

The current AgentENV native consumer still requires a cacheable readable/seekable
file. It will reject this target NC device rather than bypass its checks. A
device-aware provider/consumer, safe full-content verification and lease integration
are still required before this FC patch can be connected to that path.

## Source and validation

`baseline.json` pins the exact four reviewed source files by normalized SHA256;
it is not an attestation that a target binary came from an inferred upstream tag.
`native-pmem-fd-v1.patch` adds `native_fd.rs` and changes those four files.
No dependencies, lockfile, device permissions or deployed binaries are changed.

To reproduce the patch from a matching complete FC source tree:

```sh
python3 -I -B make_patch.py /absolute/firecracker-source /absolute/new-native.patch
```

The generator reads sources and creates a new output only. It rejects changed
input files and existing outputs. Review the patch, then use normal `git apply
--check` and build/test in an isolated FC checkout. Applying a patch does not
establish that a full FC build succeeds.

Four portable parser/contract tests executed locally; Linux ARM64 mapping code
and the Linux descriptor-lifecycle test type-checked. The Linux test uses
`/dev/zero` as a local plumbing fixture and was not executed on Windows. It must
never be labeled UB hardware proof. Patch application against the pinned source
copy and source-mismatch refusal were checked. Full-build status is recorded in
the task report and must be kept separate from these component checks.

Do not deploy over a running FC binary or enable a Runtime with this patch alone.
Next acceptance requires a matching independently built FC, provider/consumer
integration and bounded KVM/Guest tests, followed by durable lifecycle work.
