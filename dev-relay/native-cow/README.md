# Native CoW experimental relay

Latest: A_native_parent_once_v1.py --run in a new ordinary A SSH session after
closing the deployment/health session (keep the separate UB publisher alive).
It first checks the installed native Runtime using health --post-disconnect,
which must not recreate a missing host proxy. It reads the saved API port and
requires the current immutable definition to have rootfs sharing disabled.

The run verifies the existing digest-pinned PyPika OCI directory without any
image download, checks free global ublk slots and the new unit's memlock limit,
then makes at most one 1-vCPU/512-MiB cold-create request to the NEW Runtime.
It runs a PyPika import inside that Guest, captures one parent snapshot and
records committed memory/rootfs layer metadata. Only a sandbox confirmed by
this run's unique metadata may be deleted. Unknown create outcomes get one
bounded reconciliation query and are preserved without new-name retries.
Pending receipts, old reports and the resulting snapshot stay available.

No SDK calls, existing-service changes, driver settings, global cache dropping,
old-device cleanup, original Runtime Guest requests or B actions. This is the
new Runtime's ordinary-rootfs lifecycle and real-input preparation, not shared
rootfs activation, cross-node memfile CoW or memory-benefit measurement. Partial
results and missing metadata remain explicit. Default invocation is plan only.

SHA256: 243977c9f9f727ba0e04b504e66b285e413a09d5d787c2784f72b8fd3d62af77
