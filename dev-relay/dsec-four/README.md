# Repaired Host-file DSec four-template measurement

This is an A-only experiment entry. It does not allocate UB memory, deploy B,
replace any service, or claim cross-node physical sharing. It uses the repaired
Runtime core `268104ecc65080d776c2301e09e7902686ac4253` and the retained original
four-template inputs. The existing Firecracker, verifier, CLI and ublk binaries
remain from the successful `eb2301e7` release.

## Prerequisites

First use the published repair entry's `prepare`, printed root activation, and
`validate` stages. This four-template entry rejects a mere healthy service:
`dsec-real-template-smoke-v2/return.json` must confirm the real-template cold
start, DAX/exec, snapshot, pair restore, private upper isolation, unchanged base,
and owned Guest release, under the exact current activation identity.

Old failed smoke evidence is retained by the repair entry. This entry never
resolves that old pending request or retries it. Do not delete old journals to
make a prerequisite pass.

## Human execution after the prerequisites pass

Use the fixed published `A_dsec_four_v4.py`, as ordinary `jwk` on A:

```
python3 -I -B A_dsec_four_v4.py plan
python3 -I -B A_dsec_four_v4.py parents
python3 -I -B A_dsec_four_v4.py replay
```

`parents` cold-starts each of the four retained original OCI sources, captures
one clean parent, then deletes that owned Guest before proceeding. It does not
reuse the smoke snapshot containing functional-test writes. It retains all four
new parent snapshots and all source files. No workload replay occurs in parents.

`replay` creates an observation plan and prints one complete
`DSEC_FOUR_READONLY_ROOT` block. Run that block in the A root terminal within
600 seconds and leave both terminals open. Root only observes the scoped
Runtime/Guest processes and immutable file residency; it never creates or
deletes a Guest, stops a service, changes permissions on other files, invokes
the SDK or evicts cache. The ordinary controller restores two children per
template, runs the original recorded workloads concurrently, checks private
upper isolation after measurement, and cleans up its registered Guests.

The root observer exits after owner completion or its bounded three-hour limit.
The owner checks observer liveness. A failed or stopped observer does not mean
Guest cleanup passed; inspect the separate controller receipt.

## Outputs and interpretation

Under the isolated deployment's `dsec-four-v1/`:

- `parents-return.json`, `templates.json`, per-case journals: clean-parent scope.
- `single-a/report.json`, `single-a/state.json`, `single-a/commands/`: replay,
  exact Guest return codes, timeouts, private stdout/stderr and cleanup evidence.
- `root-observations.jsonl`, `observer-return.json`: bounded root observation.
- `comparison-input.private.json`, `measurement-report.md`: derived report.
- `api-errors.jsonl`: bounded, credential-redacted failed API responses.

Report regeneration is read-only with respect to services and Guests:

```
python3 -I -B A_dsec_four_v4.py report
```

After returning the private output, the separate local-only comparator can read
the original memory-recheck JSON without modifying it:

```
python compare_dsec_reference.py --candidate comparison-input.private.json --original memory-recheck256.json --original-sha256 VERIFIED_ORIGINAL_SHA256 --output-directory new-private-comparison
```

This comparator needs `dsec_report.py` beside it. It preserves observed signed
differences and labels them historical. It requires explicit CPU/RAM evidence
and exact per-command outcomes for full same-workload acceptance. Original
aggregate-only reports do not supply those missing fields: they remain gaps,
even if their 8 jobs, replay hashes and aggregate nonzero counts match.
`--original-events` optionally reads a private JSON list of
`{instanceId, slot, events:[{step, returnCode, ...}]}` records. It does not fetch
or regenerate historical results. Missing data is not repaired by guessing.

Return the private JSON/Markdown to the existing chat for local comparison with
the latest original reference. Do not publish those files, the workload data,
or command logs to GitHub. Reference per-command results are not embedded in
the public packet. Equal aggregate nonzero counts alone do not pass the exact
workload comparison. Missing original event evidence remains a reported gap.

Collection separates actual 4GiB Guest RAM VMAs, whole-FC RSS/PSS, identified
read-only PMEM VMAs, whole Host-file residency, upper cache, Runtime/provider
and collector costs. Whole-FC PSS contains PMEM mappings; PMEM mappings overlap
Host file cache. These columns are not additive. The raw file cache is observed
using PROT_NONE/mincore, but preparation's content verification may already
have warmed it. Absolute base costs and pre-replay samples remain in the log.

Heavy RAM/cache observations are scheduled about every15 seconds, with actual
scan start/end timestamps. Light process/Host observations target about1 second;
this is not a hard realtime interval. A missing pressure field does not discard
meminfo. Missing VMA classification is null. No PFNs are exported. DAX actual
file-access sets are not collected, so their resident intersection/union and
global physical net savings remain null. Two Hosts running this file-backed
mode would still have independent Host caches.

## Failure and recovery

Never rerun `parents` or `replay` over an existing phase journal. Unknown POST
outcomes remain pending, even with empty inventory. The controller attempts
cleanup only for IDs bound to each case's durable ownership metadata. One
case's cleanup failure does not prevent attempts on the other owned cases.

After inspecting the failed phase, explicit owned cleanup is:

```
python3 -I -B A_dsec_four_v4.py cleanup --scenario single-a
```

For an interrupted parent phase use `--scenario parents`. Cleanup preserves
snapshots, base images and journals; it never clears an unacknowledged POST.
If the Runtime identity changed, recovery refuses to mutate the new process.
Unknown objects or resources need explicit reconciliation, not file deletion.
Service rollback remains the separate repair entry's reviewed rollback mode.

## Validation status

This packet has local Python3.11 syntax, contract, accounting, failure-gate and
simulated lifecycle/observer tests. Linux cgroup, root permissions, KVM/DAX,
native repaired build, current deployment activation and real workload replay
have not been executed by the assistant. The target machines are accessible
only through the user's manual relay. Passing local tests is not target
acceptance or evidence of positive savings.


## v2 memory accounting and failure preservation

v2 additionally identifies the memory block device through an actual private
Guest file VMA's dev/inode, checks its block capacity and process lifetime,
then deduplicates mincore observations across Guests sharing that device.
Missing or replaced bindings are NA. When Guests exit it never reopens their
former device numbers. Compare this device-cache ledger with Host Buffers;
it can overlap Guest file-backed RAM and must not be added again to PSS.

Committed memory lower files come from the four pinned parent records and the
exact managed-layer repository naming rule. Their identity/size is checked;
cache measurement does not rehash or read payloads. These files are tracked
separately from the block-device cache and from the raw PMEM rootfs files.
Runtime and descendant ublk daemon PSS, provider PSS, observer and ordinary
controller PSS are explicit categories that overlap their cgroup charges.

If a replay finalizer fails, v2 writes a stopped report with the pending case
journals, does not send a second implicit cleanup, and preserves uncertainty.
It cannot overwrite an older run's report when a repeated phase is refused.
Known temporary CLI credentials are removed within their fixed scoped path;
unknown credential metadata is preserved and reported. A dead root observer
is detected immediately from its final receipt, not just a liveness timeout.


## v3 optional two-child Fork lifecycle

After `parents` succeeds, the same entry accepts:

```
python3 -I -B A_dsec_four_v4.py fork-check
```

This restores one disposable source from the first clean parent snapshot, writes
only that source's private upper, and sends exactly one Fork request with count2.
The pinned Runtime starts those two children with join_all. The check verifies
source resume, both children after source deletion, one child's copy-up while
its sibling remains unchanged, and the survivor after deleting the writer.
At most3 Guests coexist; no new catalog snapshots are created, and the retained
clean parent is not modified. Guest300s/CLI330s limits remain unchanged. Only the
first raw base is content-checked before/after, which warms it and is reported as
functional setup rather than a cold-cache performance test.

A successful result is DSEC_FORK_PAIR_PASSED_OWNED_GUESTS_RELEASED. Unknown POST
outcomes are not retried. A complete two-child acknowledgment is durable before
GET checks; recovery can use it after client interruption. A partial response
retains uncertainty about the failed sibling while allowing cleanup of known,
ownership-verified IDs. It never resolves a partial Fork just because inventory
is empty. Explicit cleanup is the same entry with `cleanup --scenario fork-check`.
No unknown object is swept by name or host-wide enumeration.

`parents`, `fork-check`, then `replay` may be chained with shell `&&` after the
repaired smoke passes. If any phase fails, the next phase must not start. Existing
phase directories remain non-repeatable; inspect/recover them rather than rerun.
This function checks single-host pmem lifetimes, not cross-host UB references,
external provider loss, repository cache eviction or automatic UB republishing.


## v4 read-only original-outcome supplement

The same entry can read a previously finalized original256 report, its existing
commands/NNN-events.jsonl files, and the hash-bound parent catalog resources:

```
python3 -I -B A_dsec_four_v4.py reference --original-report /home/jwk/agent/relay/reports/EXACT_ORIGINAL_REPORT/combined-summary.json --original-sha256 VERIFIED_REPORT_SHA256
```

The concrete path/hash belong in the user's local launch command, not in this
public packet. Only the declared node-a-memory-256-* report scope is accepted.
This mode does not call any service API, start Guests, rebuild templates, read
command stdout/stderr, or modify the original report/catalog. It writes one
private supplement in the new experiment directory. Missing event files or
changed catalog hashes remain explicit gaps; CPU/RAM values are not filled
from constants. Existing supplements are preserved rather than overwritten.

The candidate report includes that private supplement when present, so the
user can return the normal single candidate JSON. The local comparator binds
it to the original wrapper's full-evidence report hash, run, Sandbox IDs,
replay hashes and catalog hashes before merging copied resource/event fields.
It never rewrites the original source JSON. A separate --original-supplement
file is also accepted. No old experiment needs rerunning merely to retrieve
its still-existing recorded outcomes.
