# Four-template host lower page-cache recheck

This is an experiment controller for the same four completed original AgentENV
templates, two Guests per template. It reuses the already calibrated ARM64
observer binary `eed36d01...`; there is no Rust build, image download, UB call,
kernel/module change, or B operation. The earlier results are retained.

## Questions and measurement definitions

1. Is the target base page size really 4096 bytes? Read `SC_PAGESIZE` on the
   target; fail if it differs. Collect kernel release and underlying block queue
   sizes/read-ahead settings separately. A 256KiB request, read-ahead setting or
   aggregation cell does not establish a 256KiB base page or actual folio size.
2. Can the selected lower inodes be made cold? As their ordinary owner, issue
   one `POSIX_FADV_DONTNEED` per exact verified inode. Scan complete file residency
   before and after. Require zero observed resident pages after each pass.
   The advice is not assumed to succeed. Dirty, pinned or concurrently accessed
   pages can remain; preserve evidence and stop without a cold-run claim.
3. Does attributed residency reconcile with full lower-file residency? Query
   each lower's full `mincore` vector once per checkpoint. Derive both quantities
   from that same vector. Preserve compressed 0/1 vectors, file identities and
   per-file monotonic time spans so the report can be independently recalculated.
4. Does the alternative 256KiB representation agree? Sum actual resident 4KiB
   subpages inside each 256KiB cell; this must equal the 4KiB total. Also report
   the capacity of cells containing any qualifying page, explicitly an upper
   bound. Two Guests reading different 4KiB pages in the same cell have zero
   exact common pages even though the coarse cell intersects.

For each template, `F` is full lower-file residency, `U` is the accessed-resident
union, and `I` is the accessed-resident intersection. All use the same file cache
bitmap; `I <= U <= F`. `F-U` is resident cache outside that pair's observed reads;
it can include read-ahead, other templates' reads, or other activity. It is not
automatically attributed to read-ahead. Upper and memory metrics remain separate.

The reference kernel implementation previously reviewed checks the file cache
at PAGE_SHIFT indices, looking up the containing folio. A larger folio can cover
multiple such indices. The reference is not an attestation of the installed
kernel build. This experiment does not claim to measure folio order directly.

## Sequence and bounds

- Hold the existing replay lock. Require the previous four-template run
  `2606e4f482b44f4fb072792215ac9793` completed and restored the original service.
  Refuse if the 17-template run has a receipt; review its lifecycle first.
- Require healthy, empty original service and exact original configuration.
  Use a new `cow4-cold-node-a.pending.json` and a new report directory. Never
  clear an old pending receipt or blindly retry an uncertain operation.
- Print the literal root supervisor. It restarts only the empty original unit
  to activate the unchanged observer and later restore the original config.
- Calibrate an owned 8MiB temporary fixture: make it cold, read one 4KiB page
  using normal versus random advice, and measure the full bitmap. Cross-check
  with util-linux `fincore` when available. Only this fixture is written/fsynced
  and read as payload; it is removed after the calibration.
- Evict and verify the selected lower files before restoring Guests. Restore
  the same eight Guests, bind their actual lower identities, then evict/verify
  again immediately before replay. Preserve the cache state caused by restoration
  in the second checkpoint's before vector.
- Run the same continuous replay, sampling full lower cache and attribution
  approximately every 15 seconds, process RSS/PSS approximately every second.
  Keep lower layer counts, lengths, upper file/allocated/resident metrics.
- At the end compare `mincore -> fincore -> mincore` for each lower inode.
  Report missing tools and every discrepancy. These are sequential observations
  by different clients of the same kernel interface, not an independent physical
  RAM oracle. Full acceptance requires all three counts agree for every file.
- Release only this run's Guests; restore the exact original configuration and
  healthy service; verify the observer exited and other service identities did
  not change. Keep reports. No automatic retry.

## Side effects and limits

Targeted cache eviction changes the cache state of those inodes and can increase
subsequent I/O for any other reader of the same files. It does not modify file
contents. No global `sync`, `drop_caches`, swap action, or service-wide cache
flush is used. `DONTNEED` success alone is never a cold-state success criterion.

File scans are sequential, not an atomic whole-host snapshot. Background access
can repopulate a file after it was checked. Guest-internal caches and daemon
userspace buffers are not flushed; this is a cold **host lower-file cache** test,
not a fully cold VM/system boot. The ordinary restored-template workload stays
comparable to the previous run, but wall time includes observer overhead.

`/proc/meminfo` is sampled for context. Its host-wide `Cached` contains unrelated
files and workload activity, so it must not be equated to this cohort's `F`.
Page-rounded lower spans, stored file length, disk allocation and unique physical
cache bytes are different denominators. Folio metadata, allocator rounding and
UB global physical savings remain unmeasured.

Local Python contract checks are not Linux syscall, eviction, or Guest execution
validation. Actual target receipts and bitmap data are required to conclude
whether the previous measurements reconcile after cold initialization.
