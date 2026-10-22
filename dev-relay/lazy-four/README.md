# Four-template, two-node ordinary/lazy Guest comparison

This experimental entry runs the same four existing committed snapshots and
recorded private workloads on two nodes. Each round has eight Guests per node,
two per template, each with two vCPUs and 4 GiB RAM. It runs an ordinary lower
baseline followed by a shared demand-filled UB lower cache. This is not a
storage microbenchmark, native pmem/DAX, or cross-node Guest RAM CoW.

The source repository and private workload are read-only inputs. Snapshot
records, VM state, complete committed rootfs layers (including capture tails)
and ordinary memory layers are copied into an independent repository. No live
database, cross-deployment hardlinks, original Guest creation or original
Runtime restart is used. Both rounds reuse the same imported snapshots and the
same existing tools disk contents. No business image is rebuilt.

## Prerequisites and entry

Use the previously delivered dedicated user SSH setup. The coordinator uses
its pinned host identity and dedicated key, with forwarding and PTY disabled.
Metadata is multiplexed over an SSH **command**, not a forwarded TCP port.
The author's workstation does not connect to the target hosts.

The existing coordinated binary build must have completed. The private
four-template selection written before the earlier native image exports is
reused; those exports are not required. Do not rerun the old preparation.
Runtime/daemon/Firecracker binary provenance stays at the existing `32ce41c`
build. The lazy provider is Python code added by core commit `3aa0d871`.

Run the pinned `lazy_four_rollout.py run-a --run` entry as the ordinary user on
A. It downloads only fixed public helpers, packages the selected private input,
transfers it to B over authenticated SSH, prepares isolated deployments and the
provider, and prints **one root supervisor command per node**. Run those two
commands in the corresponding existing root terminals and leave all three
terminals open. No passwords or private credentials belong in returned output.

The root supervisors accept only fixed operations, not shell commands: start
the own baseline Runtime, observe the eight journal/API-bound Guests, stop the
empty own Runtime and its verified proxy, start the ordinary-user provider,
start the own lazy Runtime, and finish supervision. They check existing service
identities and do not operate on unrelated units. Runtime launch uses the
already reviewed network/mount capability scope; providers have no capabilities
and only the existing SDK service group. The same per-node SDK mutex is held
for the provider's entire lifetime. The exact older disposable generation is
retired through the existing two-sided acknowledgement procedure.

## Round controls and measurements

- Every round admits eight actual Guests on each node, then holds both nodes
  at ready and completed measurement gates. These are bounded, non-atomic
  observation windows, not synchronized instruction execution.
- Both rounds explicitly omit native rootfs bindings and UB memory replicas.
  The lazy round alone sets the complete rootfs replica index. Every actual
  Guest lower descriptor must match; repository fallback is disabled.
- Before Guest admission, scoped `posix_fadvise` is applied only to the new
  independent immutable lower copies, and owner `mincore` must observe zero
  residency. No global cache clearing occurs. The own Runtime/daemon is fully
  stopped between rounds to close retained device-pool FDs. Warm/prewarm
  Firecracker pools are disabled.
- The pool is fixed at 256 MiB before replay, with a 512 MiB post-map coverage
  inspection limit, not a hard physical quota. Fills use 64 KiB chunks. Offline
  full/chunk hashes and per-layer direct-I/O calibration precede measurement;
  startup does not read source payload into the pool. B imports the same pool.
- Whole ordinary lower-file residency is sampled per node after inode dedup,
  alongside Host memory/pressure, actual Guest RAM VMA and whole-FC RSS/PSS,
  private upper observations, provider counters/RSS/PSS and Runtime charges.
  Whole-file residency is **not** a per-Guest actual-access intersection.
- Commands, delays, completion counts and failures are retained. Finishing the
  replay does not imply all commands/tests exited zero. Actual sample counts
  are used; missing observations remain missing.

The report compares sixteen Guests with sixteen Guests. Old single-node
eight-Guest measurements are only historical background. Local lower cache
reduction can be positive or negative. SDK coverage is counted once for the
shared object and shown in a separate budget model. Coverage, logical pool size
and ready bytes are not measured physical increments. Global physical net
savings remain unavailable without complete, non-overlapping physical charges.

## Results and normal release

The coordinator prints the comparison directory containing `comparison.json`
and `comparison.md`. It retains per-node complete command logs, actual samples,
root supervision receipts, API lifecycle journals and transfer checksums. Rootfs
checkpoints and both gate samples are included in each returned node report.
Private files are never published to GitHub.

Normal completion stops only the new Runtime/proxy on both nodes, releases B's
broker/mapping first, then retires A's pool after acknowledged reader release.
Only then does it stop metadata transport and finish root supervision. Imported
snapshots, private input and logs remain on disk for audit/reuse. No original
service or data needs to be restored because none was replaced.

## Interrupted runs

Do not rerun the whole coordinator or delete pending directories. Unknown API
POST/DELETE outcomes, SDK journals and pins are preserved; an empty inventory or
a lost connection is not proof of release. The metadata transport is retained
on failure so explicit reader release remains possible; its own PID/start tick
and script hash are recorded. Never kill an arbitrary process with that name.

For an acknowledged existing cohort, the same pinned
`lazy_four_cohort.py cleanup --node <node> --scenario <off|lazy> --run` can
reconcile only its persisted API responses and known Guest IDs. It refuses a
different Runtime/boot/configuration. It does not delete imported templates.
After confirmed cleanup, the prepared service helper's `rollback-plan` emits a
scoped root block for the empty own Runtime and exact proxy when the automatic
supervisor has already stopped. It preserves all files and UB objects.

With the own Runtime stopped and the metadata channel alive, use the pinned
provider `retire --node node-b --run` before `retire --node node-a --run`.
Uncertain retirement intents and unresolved pins require receipt inspection,
not another allocation or automatic expiry. Component logs explain the exact
stop; a partial run is not a completed comparison.

## Validation boundary

Local tests cover protocol bounds/no replay of lost metadata requests, complete
snapshot dependency sets, real tar/hash round trips, corruption refusal,
eight-Guest lifecycle and two-node gates, environment selection, root operation
whitelists, binding mismatches and report acceptance. Linux ownership/syscalls,
SDK direct I/O, actual two-node Guest replay and physical/performance results
still require execution on the two target machines. No target pass or positive
benefit is inferred from these local tests.
