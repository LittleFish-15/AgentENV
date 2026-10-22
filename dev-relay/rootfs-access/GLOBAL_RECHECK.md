# Four-template global page-cache comparison and time-series output

Use `cow4_global_cache_once.py run --quiet-window-confirmed --accept-nonzero-baseline` as the ordinary
operator on A. The explicit flag declares that the operator has arranged a
window without other experiments on A. It is not automated proof of host
quietness. The program never stops other services to obtain such a window.

## V2: measured residual baseline after the first real attempt

The first global run `5a6b79e3138840f6849ed94be3a3b536` stopped before replay
because 3,989,504 bytes remained resident after the first completed drop. All
eight Guests exited and the original service/config were restored. Requiring
absolute zero was too strong for the intended change-over-time experiment.
V2 explicitly accepts a measured nonzero baseline, **does not claim an all-zero
cold start**, and keeps the previous attempt and its receipt unchanged. Before
a new run it verifies the exact prior failure, zero replay actions, eight HTTP
404s, exited scoped processes and the confirmed restored Runtime identity.
It uses a new `cow4-global-cache-v2-node-a.pending.json` receipt.

For each phase preserve the initial page set B0, then separately count B0 pages
currently resident, B0 pages currently absent, and resident pages outside B0.
Net change equals the last quantity minus B0 pages currently absent. Common
read-resident pages are also split into B0 and non-B0 parts. No value is silently
subtracted from the reported absolute cache size. A page recycled and reloaded
between snapshots cannot be distinguished from uninterrupted residency.

This supersedes the *execution plan* of the scoped-cold script, but preserves
all prior evidence. It uses a new pending receipt and report directory. It
refuses an existing scoped-cold or 17-template pending receipt for lifecycle
review, rather than deleting or silently replacing it.

## Operations

1. Reuse the original service, four ready templates, and calibrated observer
   binary `eed36d01...`. No compilation, download of images, UB SDK use or B
   operation. Verify the original service is healthy and empty.
2. Print the literal root supervisor. It temporarily activates that same
   observer by changing only the original service's daemon path, with the
   established scoped cleanup and exact config restoration protocol.
3. Run an owned 8MiB mincore fixture calibration, then restore/bind eight Guests.
   Start approximately one-second host sampling before Guest admission.
4. Root validates the fixed eight Guests and unchanged other service identities.
   Execute `/usr/bin/sync` (120-second subprocess timeout), then write **1** to
   `/proc/sys/vm/drop_caches`. Record intent, before/after counts and timestamps.
   This is host-wide and can increase I/O/latency for every cache user on A.
   Do not assume a successful write emptied all caches.
5. Check all target lower files with full mincore vectors. Preserve actual
   residual residency and classify the baseline as zero or nonzero. Hold the eight Guests idle for
   at least 60 seconds, sampling host counts, lower reads/residency and processes.
6. Repeat the same root operation once before replay. The root state machine
   rejects missing/reversed/repeated phases, an incomplete control interval,
   changed Guest ownership or changed other service identities. It permits at
   most two global drops and never uses values 2 or 3.
7. Run the same continuous trajectories with eight Guests. Host counts are
   sampled approximately every second, full lower cache and attribution
   approximately every 15 seconds, process RSS/PSS approximately every second.
   Actual timestamps and scan durations are retained, not resampled or padded.
8. Compare final per-file mincore/fincore/mincore observations. Release only
   this run's Guests, restore exact original config/healthy service, and check
   observer exit and other services' identities. No third cache drop or retry.

The root body ends with `COW4_GLOBAL_V2_ROOT`. Keep both terminals open; no `done`
input. Stop reports preserve evidence. Do not manually drop caches, restart
services or delete pending receipts while the experiment is running.

## Measurements

`Cached`, `Buffers`, `Shmem`, `SReclaimable`, `Dirty`, `Writeback`, `MemAvailable`
and `SwapCached` are stored separately. `Cached` is the host comparison series;
it is not renamed to rootfs cache or combined blindly with `buff/cache`.

All rootfs lower residency and attributed read intersections use the same
complete per-file mincore bitmap. Files are deduplicated across templates by
inode for global totals. Shared-page sets are globally unioned, not added per
template. The compact JSON/CSV also retains template IDs and sandbox IDs.

Known auxiliary **ordinary-file** cache includes memory lower files, rootfs
upper data/index files, and this run's trace/sampling/command output files.
Mutable files are measured over an observed prefix with growth recorded. File
errors remain explicit; incomplete auxiliary totals do not produce a fake zero
or numeric unexplained residual. Memory block-device cache and all other host
files are not exhaustively attributed; do not add Guest RSS to these values.

Rootfs and auxiliary measurements are sequential. The host before/after the
lower scan is retained. The unexplained delta is only a diagnostic residual,
not an exact physical accounting identity. Idle-control averages are not
subtracted from replay as if background behavior were constant.

4KiB comes from checked target `SC_PAGESIZE`. The 256KiB comparison groups the
same bitmap into 64-page cells. Actual resident subpage sums must conserve the
4KiB count; capacity of common cells is only a coarse upper bound. Request-size
histograms report userspace successful backing reads, not physical I/O or folio
orders. Kernel release and queue/read-ahead settings are separate evidence.

## Files and plotting

- `combined-summary.json`: summary plus embedded compact `cache_timeseries`.
- `combined-summary.md`: phase tables, lower/upper and RSS/PSS summaries.
- `cache-timeseries.json`: standalone time-series evidence.
- `host-cache-timeseries.csv`, `file-cache-timeseries.csv`,
  `template-cache-timeseries.csv`: actual observations for further plotting.
- Raw JSONL, trace, cold checkpoints and residency bitmaps remain on A.

Return `combined-summary.json` and both final terminal receipts. No ZIP or
plotting package installation on A is needed. On the analysis workstation,
`plot_cache_timeline.py INPUT OUTPUT_DIRECTORY` uses matplotlib to create:

1. `cache-global-absolute.png/svg`: aligned host and rootfs cache panels with
   both global cache-clear markers.
2. `cache-delta-comparison.png/svg`: idle and replay changes from their own T0.
3. `rootfs-per-template.png/svg`: each template's complete lower cache, two
   sandbox read-resident sets, union and intersection.
4. `cache-granularity-check.png/svg`: exact common 4KiB pages versus the
   256KiB common-cell capacity upper bound.
5. `cache-baseline-components.png/svg`: measured initial residual pages,
   pages outside that initial set, and the resulting net residency change.

PNG/SVG plots use actual timestamps and preserve missing-value gaps. No
smoothing, data-point padding or synthetic experimental results are allowed.
Any synthetic layout fixture must be conspicuously watermarked and kept out of
the experimental report. Full acceptance additionally checks both timeline
phases, all four pairs' RSS/PSS coverage, exact root drop count, final per-file
cross-checks and original-service restoration. Local tests/plot layout QA do
not constitute target Linux, cache-clear or Guest execution validation.
