# DSec Host-file pagecache component comparison

`dsec_host_pagecache_once.py --run` prepares one A-node comparison from retained
successful `cache-compare-v2` inputs. It prints a reviewed root block for a new
capability-free KVM transient unit. The caller executes that block separately.
No service binary is replaced; no SDK, UB allocation, mount, kernel change,
networked Guest, or global cache drop is performed.

Both block and pmem modes inherit the same pinned ordinary Host file. The pmem
mode uses Firecracker's existing shared-file mapping and Guest filesystem DAX.
Host FS-DAX and physical persistent-memory hardware are not required. Four groups
run once: one/two Guests in block/pmem mode, reading the same 8MiB payload and
holding for 30 seconds. Maximum simultaneous Guests: two. Unit budget: 600s and
1536MiB. Inputs are hashed/prewarmed; this is not a cold Host-cache experiment.

The new directory is `/home/jwk/agent/r/dsec-host-pagecache-node-a-v1`.
`results/return.json` contains all observations; `results/report.md` contains the
component comparison. Existing directories and all previous evidence are
preserved. Failures stop subsequent groups and keep partial reports/logs.
The script verifies Guest DAX/checksums and each pmem FC's same-inode, shared
readonly Host-file VMA. Host-file residence and whole-FC PSS are separate fields,
not additive physical accounts. Global savings, original snapshot-CoW comparison,
four-template workloads and cross-node Guest-RAM CoW remain unaccepted.

For interruption, stop only the new `jwk-dsec-pagecache-node-a-v1.service` unit.
Do not delete the stage or stop other services. The root command also has a
runtime limit and kills its own control group at termination. Keep partial
results for review before a rerun; preparation refuses to overwrite them.

This is the DSec mechanism control described in arXiv:2609.22978 §5.2, not a new
UB physical-sharing result. Local tests are protocol/accounting simulations,
not target execution. No private benchmark or captured target report is included.
