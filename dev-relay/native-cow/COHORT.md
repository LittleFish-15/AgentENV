# Bounded public workload cohort and explicit-gap report

This runner tests a real API lifecycle once the declared services and same-image
inputs are present. It does not implement native Guest RAM private CoW, bootstrap
the two machines, or establish global memory savings by itself.

Place `native_cohort.py`, `cohort_engine.py`, `ram_observer.py`, and
`public_workload.py` together under `/home/jwk/agent`. The entry verifies the
other three against embedded SHA256 pins. Use the same files on both nodes.
Everything defaults to plan only. Run as the ordinary experiment user:

```sh
python3 -I -B native_cohort.py --node node-a --variant original --run
python3 -I -B native_cohort.py --node node-a --variant native --run
```

The B commands use `--node node-b`. These are individual cohort entries; the
cross-node coordinator is not yet supplied by this revision. Do not describe
four independently executed cohorts as a synchronized two-node experiment.

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

Every mutation is preceded by a durable intent. An uncertain response is never
automatically retried. Known sandbox IDs are deleted only after checking their
batch metadata and confirmed absent with GET 404. Empty inventory after a
timeout does not prove a late create/Fork cannot complete. Such a run keeps its
pending request and refuses another run; do not erase the journal to retry.
An unresolved DELETE is checked for GET 404 but never sent twice by cleanup.

Successful completion means `COHORT_FUNCTIONAL_PASS_SNAPSHOTS_RETAINED`, not a
memory-sharing acceptance. The explicit capture remains in the repository;
any Fork-created snapshots also remain governed by Runtime semantics. Provider
retirement refuses retained catalog records. Runtime rollback preserves them.
No script in this revision deletes retained snapshots or implements distributed
snapshot garbage collection. Empty UUID `.lock` files left by a removed POSIX
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
charge, private upper residency, complete helper cost and external sharing are
also missing. The report leaves global net saving and cross-node sharing
acceptance unavailable, even if a process or cgroup metric improves.

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
