# A original pair preparation and observations

`cow_pair_once.py` uses the successful parent receipt and the existing immutable
`/home/jwk/agent/cow_parent_424b012.py` helper (checked by SHA256 before import).
Run as ordinary jwk on server1. It requires an initially empty original Runtime,
a committed 1-vCPU/512-MiB parent, and no prior pair receipt. No downloads occur
inside the script, and no root/service/UB operations are performed.

The parent catalog path is `state/snapshot-store/repository/catalog/records`.
The earlier parent collector omitted `repository`; its FileNotFoundError was a
collector failure, not evidence of an absent snapshot. Source:
`src/snapshot/repository/backends/mod.rs:74` appends `repository`;
`src/snapshot/repository/backends/posixfs/layout.rs:30` defines catalog/records;
`src/snapshot/types/snapshot.rs:322` and `:470` define committed layer records.

The script performs at most two POST /sandboxes calls with the same templateID,
900-second TTL and Internet access disabled (`allow_internet_access`, the actual
NewSandbox serde field). Each child imports pypika. It writes a distinct 4-MiB
file to the same fresh pathname in each child, verifies the other child cannot
see the first write, and verifies both retain their different contents. It
deletes only returned child IDs after checking this run's ownership metadata and
confirms 404. It preserves the parent snapshot and all prior receipts. Unknown
create outcomes are never arbitrarily deleted or retried.

Three samples are taken at each of six stages: before restore, first restore,
second restore, child1 write, both writes and cleanup. Measurements include:

- memory/rootfs catalog layer identity and declared stored size;
- managed regular-file length, st_blocks allocation and mincore resident pages;
- file cache totals deduplicated by local device/inode, with per-kind subtotals;
- only the original unit's Firecracker PID/start-time/UID and readable smaps
  accounting, with no command-line, environment or process memory collection.

mincore maps files without touching data. It measures stored-file page cache,
not the memory/rootfs ublk device cache. Samples are not atomic. Same-inode
references count once in the combined total; kind subtotals are not necessarily
additive. External layers and inaccessible files remain explicitly unresolved.
Whole-process RSS/PSS is not attributed to Guest RAM. Raw selected VMA metadata
is retained in stage JSON files; the return report gives compact summaries.

This is a restore/isolation and measurement-preparation stage. It does **not**
complete physical memfile sharing acceptance, RAM first-write/multi-generation
tests, complete rootfs upper/device-cache accounting, or the colleague's selected
agent_replay trajectory. Those remain required follow-up work. Physical sharing
bytes/ratios stay null; no Guest or host-cache subtraction is used to invent them.
No cache eviction, drop_caches, memory pressure or content hashing of layer data
is performed during sampling.

Success: `ORIGINAL_PAIR_RESTORE_FILE_ISOLATION_COMPLETED_FULL_MEASUREMENT_PENDING`.
Return the complete BEGIN/END report. Failure: preserve receipt and return the
report; do not rerun blindly. The source parent remains usable without rebuilding.

Tests: `python3 -I -B dev-relay/test_cow_pair_once.py`. API/Guest lifecycle tests
use doubles. Linux mincore, permissions, API restores and isolation are not
validated by those local tests; target receipts provide that evidence.
