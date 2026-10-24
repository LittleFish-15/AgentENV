# Single-host DSec four-template measurement after authentication fix

This entry continues only after the retained real-template restore/isolation/release
gate has completed under core `2c2c0ea573f97a0ce8fc64f2dfb79d60b7089a14`.
The Runtime binary SHA is pinned separately from the core source commit.
All existing v5 collection/replay/lifecycle helpers are preserved byte-for-byte.
The changes are release admission, complete smoke-result checks, an independent
`dsec-four-auth-v1` result directory, and sequential `all` mode.

## Human relay

Run `A_dsec_four_auth_v1.py all` as ordinary jwk on A. This creates four clean
parents sequentially from retained original OCI inputs, captures and releases
each parent, then restores two children per template and runs the same retained
private workloads. Maximum concurrent replay Guests is eight, two CPU/four GiB
each. Existing images are not rebuilt, UB is not called, B is not accessed,
and services are not replaced. New clean captures are needed: the functional
smoke capture intentionally contains validation writes and is not a clean
business comparison parent.

After parent preparation, replay prints one complete DSEC_FOUR_READONLY_ROOT
block. Execute that exact block in an A root terminal within 600 seconds;
leave both terminals attached. Root observes only this scoped cohort, and
does not manage services, evict caches, load modules or create/delete Guests.
Guest command timeout 300 seconds and CLI timeout 330 seconds are unchanged.

Successful replay status is NATIVE_FOUR_REPLAY_COMPLETED_OWNED_GUESTS_RELEASED.
Derived report generation must also succeed; a derivation failure returns
nonzero while preserving replay and cleanup evidence.

## Measurements and limits

The retained collectors separate actual Guest RAM VMAs, whole-FC RSS/PSS and
categories, identified PMEM file mappings, Host meminfo, whole-file lower
residency, memory storage files, deduplicated memory block-device residency,
private upper, Runtime/provider and observer costs. Light sampling targets
one second; heavier sampling approximately fifteen seconds, with actual times.
No PFNs are exported. Actual DAX file-access sets are not collected; their
access/resident unions/intersections remain NA. File residency is not access.
Preparation may warm complete raw bases, and their absolute cost is retained.

This run is the candidate side of the planned original/candidate comparison.
It does NOT execute a new original baseline, does not establish same-workload
benefit by itself, and never labels the modified off baseline as original.
Fresh matching original execution and per-command/input comparability remain
separate gates before a complete paired benefit claim. Historical comparison
must retain its different-date/cache-state limits.

## Outputs and recovery

All target outputs stay under the dedicated deployment's `dsec-four-auth-v1`:
parents-return.json, templates.json, single-a/report.json and per-case journals,
root-observations.jsonl, observer-return.json, comparison-input.private.json,
measurement-report.md, and private command logs. Return comparison JSON and
Markdown plus owner/root terminal receipts through the existing private relay.
Never publish workload data, credentials, host receipts or raw reports.

Any failed phase stops `all`; there is no automatic retry over an old journal.
Do not rerun `all` to clear a failure. Explicit cleanup uses the same entry:
`cleanup --scenario parents` or `cleanup --scenario single-a` according to the
failed phase. It handles only known owned resources, preserves captures and
unknown POSTs, and refuses changed Runtime identity. `report` regenerates
derived output without rerunning Guests after the observer has stopped.
Service rollback remains the separately reviewed auth update entry.

## Validation

Local Python contract, lifecycle, observer/accounting and admission tests pass.
OS/API/process examples are simulated locally; this is not Linux/KVM execution
or positive-benefit evidence. All target execution requires the human relay.
