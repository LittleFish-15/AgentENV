# Bounded public workload cohort and explicit-gap report

This runner tests a real API lifecycle once the declared services and same-image
inputs are present. It does not implement native Guest RAM private CoW, bootstrap
the two machines, or establish global memory savings by itself.

Place `native_cohort.py`, `cohort_engine.py`, `ram_observer.py`,
`public_workload.py` and `cohort_sync.py` together under `/home/jwk/agent`. The
entry verifies its loaded modules against embedded SHA256 pins. Use the same
files on both nodes.
Everything defaults to plan only. Run as the ordinary experiment user:

```sh
python3 -I -B native_cohort.py --node node-a --variant original --run
python3 -I -B native_cohort.py --node node-a --variant native --run
```

The B commands use `--node node-b`. These are individual cohort entries;
ROLLOUT.md supplies their A-side preparation/transfer/run coordinator. It holds
both nodes' two owned Guests after the workload until both post-workload samples
complete. Standalone commands without `--pair-epoch` do not join that hold.
This coordinates the residency observation interval; it does not create an
atomic hardware snapshot or synchronize workload instruction starts.

Before either variant, the coordinated deployment's `rootfs-inputs.json` must
identify the received original image. The original run uses the existing
`ae9c626` service and port 18080, verifies its installation and binary hashes,
holds the existing `cow55-replay-node-X.lock`, and requires an empty running and
paused sandbox inventory. It does not restart or reconfigure that service.
The native run requires the new `6cdac56` service, a pinned v3 rootfs binding and
the same input image. Its `cohort.lock` also excludes rollback/base retirement.

Each run does exactly one cold parent, one capture, one restore and one Fork.
The parent is removed before measuring the two children. Captures precede the
public workload. Both children read the same `/pypika` Python source tree and
construct 2,000 deterministic queries. Content/query hashes must match. Each
child writes its own `/tmp` marker; after both finish, each must see its own
marker and none of its peer's marker. This verifies private upper isolation,
not native Guest RAM CoW. The public workload is not the private replay suite.

Workload revision 2 queries effective `STATX_ATTR_DAX` before and after reading
each source file on the **same open FD**, using `statx` with `AT_EMPTY_PATH`.
It checks the returned support mask and inode/size against that FD. Missing
support, failed calls or changed effective attributes are unknown, never an
assumed non-DAX zero. Counts distinguish DAX, non-DAX and unknown files and their
cumulative read payload. The payload can contain repeated/aliased data and is
not a resident-page union or a physical sharing measurement. Both variants use
the same observer and workload source; timings include these metadata queries.
The flag is the effective access mode, not the persistent advisory inode flag.
See [Linux v6.1 DAX documentation](https://raw.githubusercontent.com/torvalds/linux/v6.1/Documentation/filesystems/dax.rst)
and [the statx UAPI layout](https://raw.githubusercontent.com/torvalds/linux/v6.1/include/uapi/linux/stat.h).

Every mutation is preceded by a durable intent. An uncertain response is never
automatically retried. Known sandbox IDs are deleted only after checking their
batch metadata and confirmed absent with GET 404. Empty inventory after a
timeout does not prove a late create/Fork cannot complete. Such a run keeps its
pending request and refuses another run; do not erase the journal to retry.
An unresolved DELETE is checked for GET 404 but never sent twice by cleanup.

For an interrupted batch, the same entry supports
`--node NODE --variant original|native --cleanup --run`. It requires the recorded
boot, Runtime PID/start time, configuration, node and private report directory
to still match. It holds the same coordination locks and issues no new create,
capture, restore or Fork. A persisted successful API response can identify an
already-created resource; only that exact identity is reconciled. Without that
response evidence an uncertain POST stays pending, even when inventory is empty.
Known owned Guests are cleaned; a still-pending DELETE is not sent again.
The original measurement report is preserved, and a separate `recovery-*.json`
records the outcome. Snapshots remain retained. This cleanup mode is not a
restart of the workload or automatic continuation of the whole rollout.

Add `--release-captures` only when you intend to discard this batch's retained
capture. The entry requires empty running/paused inventory, no unresolved
create/capture/Fork, a literal recorded snapshot UUID and the exact original
committed-record SHA. It requests `DELETE /templates/UUID` once, then requires
both GET 404 and absence of that committed record. A lost response is reconciled
by those two absence checks without another DELETE. Changed records, missing
original evidence and unrelated templates are preserved. No repository directory
is removed by the script. This explicit mode keeps the original measurement
report and records deletion in a separate recovery artifact. See CLEANUP.md.

Successful completion means `COHORT_FUNCTIONAL_PASS_SNAPSHOTS_RETAINED`, not a
memory-sharing acceptance. The explicit capture remains in the repository;
any Fork-created snapshots also remain governed by Runtime semantics. Provider
retirement refuses retained catalog records. Runtime rollback preserves them.
The explicit capture-release mode is scoped to this batch; distributed snapshot
garbage collection is not implemented. Empty UUID `.lock` files left by a removed POSIX
record are not themselves references; malformed/unknown entries still block
retirement.

Reports are in `relay/reports/cohort-NODE-VARIANT-*/report.json`. Durable state is
the native deployment's `cohort-state.json`, or
`r/cohort-original-NODE-v1/cohort-state.json` for the original. Public workload
stdout/stderr remains local. Temporary CLI credentials are removed at exit;
reports do not contain API keys. Existing services, UB publications and all
unrelated Guests/devices are preserved.

## Measurements

The collector binds Firecracker through the declared Runtime's process tree,
owned sandbox log path, UID and PID start time. It obtains actual Guest RAM
intervals via `GET /vm/guest-memory-regions` after verifying Unix socket peer
credentials, then intersects those addresses with `smaps`. Anonymous mappings
are accepted only inside those authoritative intervals. VMA clipping does not
prorate or credit whole-VMA PSS. Missing permissions/API/coverage produces NA,
never a guessed largest anonymous mapping. No raw PFNs or Guest memory content
is exported. A privileged integrated collector is not yet included, so ordinary
user restrictions can still make the RAM measurements unavailable.

Runtime `memory.current` and selected `memory.stat` values are recorded in the
same sampling interval, with non-additive overlap labeled. The separately
running UB provider is excluded by that cgroup. Guest `/proc/meminfo` appears in
workload output; Guest Cached is already part of Guest RAM. Adding it to RAM
would double count. Whole-FC RSS/PSS is separate from actual Guest RAM PSS.
During-workload samples label whether both workers or only one were unfinished
at sample start. Sampling is not atomic; this label does not establish that both
were executing throughout the whole sampling interval.

Host lower access sets and their contemporaneous residency are **not collected
by this revision**. Whole-file residency is never substituted. UB physical
charge, complete helper cost and external sharing are also missing. The report
leaves global net saving and cross-node sharing
acceptance unavailable, even if a process or cgroup metric improves.

For a bound Guest, the collector also resolves its actual
`overlaybd/image.json`, normalizes legitimate relative-parent paths, and confines
the data/index upper to that Guest's working directory. It checks upper inodes
against every bound lower and other Guest's upper. `PROT_NONE` mapping plus
`mincore` queries private Host upper cache without dereferencing file contents;
size/identity/timestamp changes during a file sample make it unavailable.
Logical and allocated file sizes are separate from resident page bytes. These
upper values may already be in the Runtime cgroup, so they are not added again.

The new provider's PID/start time, RSS/PSS, cgroup charge and SDK-journal backing
coverage are recorded separately. The provider must identify this serving
generation. A missing/not-yet-started provider is unavailable, not an assumed
zero-cost UB base. Device mappings may be absent from RSS/PSS/cgroup accounting;
SDK backing coverage is not physical allocation/residency. Both node references
to one generation must never be summed as two independently allocated bases.
The sample's end timestamp follows RAM, upper, Runtime and provider observations;
it describes an interval, not an atomic instantaneous snapshot.

Once the four reports are returned to one machine, the pure report generator
produces `comparison.json` and `comparison.md` in a new directory:

```sh
python3 -I -B cohort_report.py \
  --report A-original.json --report B-original.json \
  --report A-native.json --report B-native.json --output comparison-new
```

Comparison checks four distinct node/variant pairs, identical workload/input and
Guest output identities, successful owned cleanup and same boot per node.
Negative differences stay negative. Missing values stay NA. One cohort per
variant is descriptive evidence, not a statistical performance result.

Local validation executes request-state transitions, capture content guards,
RAM interval parsing and report arithmetic with fixtures. It does not execute
Linux KVM, UB, a target service, target filesystem, or the Guest workload.

## Coordinated post-workload hold

The coordinator creates a fresh private epoch on each node before launching its
cohort. Each worker publishes its own run/Guest IDs only after the workload and
isolation checks finish. Both readiness records must exist before either worker
is told to sample. Each publishes a digest of its actual sample and waits.
Only after both measured receipts are collected does the coordinator release
both workers into owned cleanup. The reports independently check those receipt
hashes against their own samples and matching two-node epoch.

Cancellation is an explicit private epoch record. It prevents a new create,
capture or Fork before writing an intent, while allowing owned cleanup. Failure
or a 10-minute worker hold timeout records failure and cleans only known owned
Guests. A missing peer receipt never becomes a completed common window. Control
files are immutable, bounded and private; successful duplicate control delivery
is idempotent only when bytes match. No synchronized host clock is assumed.
