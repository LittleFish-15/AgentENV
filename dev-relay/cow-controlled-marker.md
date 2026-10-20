# Controlled RAM/rootfs CoW: measurement-template preparation

This is a temporary relay experiment, not part of the upstream runtime feature.
It derives a separate measurement snapshot from the retained original PyPika
snapshot. The original template and previous measurements remain unchanged.

## Why this preparation is necessary

The original baseline proved same-node physical sharing. It did not identify a
chosen writable Guest arena or prove its virtual-to-Guest-physical mapping was
readable. Full-Guest RSS/PSS/PFN changes alone cannot attribute background memory
activity to a controlled first write. The minimum target experiment therefore
checks that a live marker process and its nonzero data survive snapshot restore,
and that the marker can report its own page metadata without new privileges.

## Fixed scope and expected behavior

Run `cow_marker_prepare.py` only on A/server1 as ordinary jwk, in
`/home/jwk/agent`. Put `cow_marker_guest.py` beside it. The existing immutable
`cow_parent_424b012.py` is required and SHA-checked. There are no downloads inside
the script, no root Host commands, no service/config/permission changes, no UB
calls and no B operations.

The script requires an empty original experimental Runtime and the retained
1-vCPU/512-MiB source snapshot. It performs at most two sequential restores and
one snapshot capture, with at most one live Guest and a 900-second sandbox TTL.

1. Restore the original source snapshot into a preparation Guest.
2. Inside that Guest, place a uniquely named marker under `/pypika`. The marker
   holds a 16-MiB private anonymous mmap filled with deterministic nonzero data,
   split into four 4-MiB segments. It creates a separate 4-MiB rootfs file and
   serves a bounded whitelist over a private Guest Unix socket. It creates no
   Host service. Its lifetime is controlled by Guest TTL/cleanup; a captured
   absolute Guest-clock expiry is deliberately avoided.
3. Check four RAM hashes and the rootfs-file hash against independently generated
   expected content. Read only that process's own Guest pagemap entries for the
   arena. Hidden/absent/swapped page metadata stops this preparation before
   capture; no permission or capability change is attempted.
4. Capture one separately named measurement snapshot and release the preparation
   Guest, verifying API 404 before creating the verifier.
5. Restore the measurement snapshot. Contact the existing restored marker;
   **do not restart or reinitialize it**. Check content, Guest server PID and arena
   virtual address, and current arena page metadata. Record whether Guest GPA
   layout stayed identical; content/mapping validity is required, identical GPA
   layout is an observation rather than a guessed invariant.
6. Release the verifier and return one report. Retain the original and new
   snapshots for the controlled-write measurements.

Success marker:
`INSTRUMENTED_SNAPSHOT_READY_MARKER_RESTORE_VERIFIED_GUESTS_RELEASED`.
This confirms the measurement input, not physical CoW write behavior.

## Side effects, failure criteria and cleanup

The Host writes only its own reports, lock/pending receipt and temporary CLI
credentials beneath the experimental root. Guest writes are confined to its own
new marker directory. 16 MiB is within the existing Guest RAM configuration,
not an added Host hard quota. Snapshot backing and filesystem overhead are
measured later, not assumed equal to payload length. Available workspace space
is checked; it is not a service-enforced quota.

There is no retry on unknown restore/capture outcome. Known sandbox IDs are
deleted only after this run's metadata marker matches, then GET404 is required.
Failure before capture releases the preparation Guest. A snapshot already
captured is preserved even if verifier checks fail. Unknown snapshot creation,
foreign metadata, incomplete deletion or existing pending state remains recorded
for review. No global device/process cleanup, receipt deletion, or original
snapshot deletion is performed. Temporary CLI credentials are removed.

Hash/GPA failures and command tails are included in the return report. Raw Guest
arena addresses stay in the private run's status artifacts; the main report gives
counts and digests. These are Guest addresses, not Host PFNs or credentials.

## Subsequent controlled-write acceptance (not executed by this preparation)

- Restore two children from this **new measurement template**, verify both begin
  with the same four RAM and rootfs hashes. The added marker changes the workload;
  do not compare its baseline directly to the previous uninstrumented 40.7-MiB
  result as an optimization gain.
- Bind Guest arena virtual pages → Guest GPA metadata → the existing verified
  Firecracker Guest-region API → Host pagemap entries. If metadata is unavailable,
  report that limitation; do not infer a target address by size alone.
- Measure both children before writes; child1 first writes RAM segment0 and its
  file; measure; repeat the identical write; measure; child2 writes disjoint RAM
  segment1 and its file; measure. Verify the other child's expected content at
  every step. Target page size and background Guest changes are reported apart.
- Capture/restore the modified child for multi-generation content inheritance,
  and verify the other branch is unchanged. Track only these owned artifacts.
- Include whole-Firecracker status.VmRSS, rollup.Pss and the user's confirmed
  template formula, alongside exact Guest/target PFN and lower/upper/cache data.
  Use phase-labelled windows and the same measurement-template ID in the report.

Local tests: `python3 -I -B dev-relay/test_cow_marker.py`. They check byte patterns,
first/repeat/disjoint mutation logic, frame bounds, expected hash contracts and
API lifecycle fault handling with doubles. They do not prove Guest daemon
persistence, Guest pagemap permission, physical isolation or snapshot behavior
on A; the target report is required for those conclusions.
