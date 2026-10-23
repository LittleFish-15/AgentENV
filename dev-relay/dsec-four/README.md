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

Use the fixed published `A_dsec_four_v1.py`, as ordinary `jwk` on A:

```
python3 -I -B A_dsec_four_v1.py plan
python3 -I -B A_dsec_four_v1.py parents
python3 -I -B A_dsec_four_v1.py replay
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
python3 -I -B A_dsec_four_v1.py report
```

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
python3 -I -B A_dsec_four_v1.py cleanup --scenario single-a
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
