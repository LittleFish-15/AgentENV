# Native CoW experimental relay

Latest: A_native_parent_once_v2.py --run. The installed native Runtime and its
post-disconnect health remain prerequisites. It verifies that the prior v1 run
stopped before any create or snapshot request; prior reports remain unchanged.

The device budget is derived from the pinned Runtime configuration and source:
the configured existing tools disk is an ordinary file (no tools ublk), fresh
Guest RAM is not restored through ublk, the cold rootfs needs at most one new
ublk device, and capture restacks that same device while writing memory to a
layer. No extra drives or resize are requested; startup prewarm is disabled.
The script requires one possible new rootfs device plus two spare slots, for
three total free slots. Changed config or nonregular/missing tools invalidates
this budget. Capacity is checked again immediately before the only POST.
This is headroom, not a reservation against concurrent allocators.

It reuses the existing verified offline PyPika OCI input, runs one 512 MiB
Guest, imports the workload, captures a parent and deletes only its own Guest.
No automatic create retry, old-device cleanup, daemon restart, driver limit,
Host permission or SDK change is performed. UB binding remains disabled for
this service lifecycle/input preparation step. No memory savings are claimed.
Core/main remain unchanged. No credentials, active UB manifests or binaries.

SHA256: 9af039c72f256230c1c371666771326f2f965f07cc4d83f6e4e7d7cb6a9de0a9
