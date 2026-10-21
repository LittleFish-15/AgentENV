# Cross-node CoW validation tools

These optional Linux tools support the core implementation candidate on
`feat/cross-node-cow-core`. They are separate from runtime source and contain no
site deployment profiles, captured measurements, SDK objects, binaries or private
workloads. **Native writable memfile CoW and complete cross-node physical savings
are not accepted by this tool release.** Code/build success is not hardware proof.

Run `python3 -I -B SCRIPT --help` for explicit parameters. Preparation/build/Guest
tools default to planning and require an explicit run flag for actions. The
collector requires explicit experiment identities and bounded inputs. Nothing
installs SDKs/packages, grants privileges, changes a kernel, restarts services or
contacts experiment nodes automatically. Use your existing authorized account and
existing tools; no elevation fallback is supplied.

| Tool | Purpose and boundary |
| --- | --- |
| `build_stage.py` | Build pinned core/FC sources in a new isolated directory. Preserve an explicit nonempty same-architecture seccomp policy. No activation. |
| `prepare_guest_tools.py` | Copy a pinned old tools ext4, inject new init/DAX checker only into the new copy, then stat/dump/hash verify. Use existing Go or an explicit SHA-pinned ARM64 checker. `runtime` and `dax-selftest` are different images. |
| `prepare_ext4_probe.py` | New synthetic 64MiB immutable lower and 64MiB private-upper input, with an 8MiB common file. Regular files only; no mount/device formatting. Not an application workload. |
| `owned_mapping_probe.py` | One new disposable 4MiB NC object; readonly/shared and private-write mapping observations in supervised children. Explicit SDK/library pin, shared coordination lock and durable pending path required. |
| `native_pmem_guest.py` | One independently configured FC Guest, same-UID provider FD/lease handoff, private copy of upper, strict serial DAX/Base markers. Requires existing KVM access. No SDK. |
| `native_pmem_guest_trace.py` | The same bounded experiment with an explicitly pinned trace runner. Original FC filters stay enabled. Diagnostic only. |
| `owned_sigsys_trace.cpp` | Compile with an existing native C++ compiler. Trace only the freshly created child and its reported descendants; never attach to unrelated processes. |
| `collect.py` | Explicit PID/start-ticks/RAM ranges and file mincore sampling. Missing permissions/masked PFNs are unknown, never zero. No whole-file cache warming or cache dropping. |
| `report.py` | Read `--evidence` and optional `--sample` JSON files and write a new report directory. No bundled laboratory data or automatic acceptance. |

## Operator sequence

The current GNU build candidate used a same-architecture musl policy and its
first native Guest stopped with SIGSYS. Building successfully therefore does
not approve that policy for GNU libc. Identify the exact rejected syscall and
validate an ABI-appropriate strict policy before deployment; never disable the
filter or silently replace it with a default-allow policy.

1. Validate exact source/binary/content hashes, available resources, existing
   permissions and lifecycle receipts. Never reuse a failed/uncertain pending
   receipt or delete it to permit another allocation. Use the same SDK lock as
   every other operation against that experiment environment.
2. Build/stage in new paths, prepare new Guest tools and trusted immutable lower
   input. An omitted filesystem binding means EROFS; explicit ext4 lowers use
   `ro,noload,dax=always`, no inline data or journal requiring replay. Guest lower
   and merged OverlayFS files must actually report DAX; there is no cache fallback.
3. Start the core provider separately, as publisher on one node and import-only
   on the other. Transfer only its portable manifest through an authorized
   channel. Use each provider's actual local socket; do not copy another node's
   Unix socket path. Import must not allocate or delete the published base.
4. Run the minimal Guest mechanism check before full runtime/workload experiments.
   Keep provider ownership and lease sockets until every exact child is reaped.
   A data-only DAX test does not prove ELF execution: separately check an actual
   executable in the immutable DAX lower and execute it without copying it up.
5. Stop new imports and release readers; importers retire first and produce real
   release receipts. The publisher retires only after every configured reader's
   exact owner/generation/manifest-bound receipt is checked. Disconnect, timeout
   or one Guest exit is not proof that the shared object is globally unused.

Example paths in your own profiles should be absolute, dedicated and short enough
for Unix sockets. Replace all example hashes and names with your measured values;
there is no supplied active manifest or target identity.

## Interpreting observations

The mapping probe's 128MiB coverage guard is checked after allocation/map and is
not a physical hard quota. A successful probe with failed private mmap is a
completed negative observation, not a CoW capability pass. Do not replace private
mapping with writable shared mapping or a full local copy and call it sharing.

For one node/boot, deduplicate each Guest's resident PFN set. Shared unique bytes,
shared participation and avoided duplicates have different denominators. Do not
compare PFNs across nodes. Rootfs common resident file offsets show a potential
reuse range; they do not establish one global physical allocation.

For net savings, match committed inputs, workload, concurrency, warmup and sample
points. Count real UB physical cost once, node-local caches/copies, Guest private
pages, uppers and auxiliary processes without overlap. Guest file cache is
already in Guest RAM. Equal hashes, FD handoff, SDK coverage, traffic or RSS alone
cannot establish net savings. The generic report leaves net physical savings NA.

The core currently refuses native pmem snapshot capture/restore and does not
supply proven native NC Guest-RAM private write handling. Platform/driver/KVM
support, ARM memory attributes, dirty tracking, executable DAX and multi-generation
lifecycle require their own acceptance. This directory is not a complete one-step
deployment or globally unique-memory verifier.

## Portable checks

Run `python3 -I -B tests/test_contracts.py`. These tests use self-contained
synthetic inputs and make no SDK/KVM/Guest calls; they are not target validation.
