# Original-only 64 KiB comparison: build stage

This directory contains development relay tooling, separate from the production
change in commit `9a2fcf6571a0266dc22a65315a3fbfbd96a562b2`. It is not part of a
cross-node CoW implementation or an upstream core patch.

`../cow4_original_io64_build.py build` is a self-contained build-only entry for
the existing ARM64 experiment host. It verifies all 804 original compiler inputs
from the previous observer build, copies them into a new directory, overlays
the eight core files from the above commit, and uses the existing offline Rust
and Cargo cache. It never changes the previous source directory, installed
binaries, services, kernel, device permissions, templates or Guests.

The existing read observer remains byte-identical, with fingerprint
`c553d631d18a01ce5511dec12e50a1a58817c92181d20f1443f17561f87a67ce`.
The original Cargo lockfile remains byte-identical too. The wrapper embeds the
readable `build_original.py` and the existing accounting helper, plus input
hashes and the eight source deltas. No private replay data or credentials are
included.

The builder runs the new configuration, protocol/client and pool-selection
tests, the observer tests and calibration, and builds both the server and the
daemon. It records candidate SHA-256 digests and the original/core provenance.
The success status means **built and staged, not deployed or experimentally
validated**. Use `status` to retrieve an existing receipt; do not remove it to
force a retry after an unknown outcome.

Return the build receipt before temporary activation. The activation controller
must bind the exact candidate hashes, preserve the original server and complete
configuration bytes, verify kernel queue limits for each owned device, and
restore the originals after the unchanged four-template/eight-Guest experiment.
Do not replace installed binaries or restart services manually from this build
receipt.

## Pinned four-template trial

The returned target build succeeded. `../cow4_original_io64_once.py` now binds
server SHA-256 `118fac40d567b07e236f6fcdff90bc8b8aa99bf2c1ae0e7998c7b608726d0517`
and daemon SHA-256 `3d6af078dc4b4ce5ad8531cfb1cb91242745bbfd300757a3197cce45e64cb3d0`.
It derives from the executed global-cache packet whose SHA-256 is
`4dc486145378f945df9a285e9bee0fe7368c147a67699b3343ce47bc8200ceb1`.
All ten prior embedded observation/lifecycle helper modules are unchanged.
`make_trial.py` reproduces the packet from that exact prior packet; the new
owner and literal-root additions are readable alongside it.

Run as the ordinary experiment user with `run --quiet-window-confirmed
--accept-nonzero-baseline`. Keep the owner terminal open and paste the printed
literal root block into the same host's root terminal within 600 seconds.
Do not run the downloaded Python file as root. No `done` input is used.
`status` reads this trial's receipt; an existing receipt blocks an implicit retry.

Only the original service is temporarily changed. The owner preserves a
hardlink to the original executable and original configuration bytes. Root
checks the current running executable inode and candidate hashes, atomically
installs the candidate, then restarts the empty original service. Before replay,
root binds all eight Guests to the original unit, local lower/upper identities,
and actual block devices. Both kernel `max_hw_sectors_kb` and `max_sectors_kb`
must be 64 for each rootfs and 256 for each memory device. Mismatch stops replay.

The original workload and observation schedule are retained: four templates,
eight Guests, continuous replay, 60-second idle control, exactly two host-wide
sync plus `drop_caches=1` operations before idle/replay, one-second host/process
sampling and nominal 15-second file-cache sampling. The quiet-window flag is
an operator declaration, not an independent proof of absent background I/O.

After owned Guests are released, root restores the exact original server inode
and configuration bytes/metadata, restarts the original service, checks health,
and verifies other service identities. Unknown binaries or remaining Guests
are preserved for explicit recovery. The receipt does not claim complete
acceptance without device checks, full sampling coverage and successful restore.
Backups, the root plan, raw measurements, JSON and Markdown remain in the new
report directory. The baseline `de320ed9ad9b4b8b9aa037ee9d4dcc8e` is preserved.

Local `test_trial.py` exercises seven control cases, including real temporary
file replacement and exact hardlink restoration. Linux UID/proc/systemd/socket
behavior is simulated in these portable tests; the target trial is pending.

## Fresh original 256 KiB control after the completed 64 KiB trial

The IO64 trial `e743a6785cfe48cbb822f8d87213f176` completed and restored the
original server. `../cow4_original_256_recheck.py` runs a new, independently
recorded control against that restored original. It uses the original server
SHA-256 `0c5478b8382289c05ab1730401eea6918420c35594604cc7131592e81ad5aeff`
and the first experiment's observer daemon SHA-256
`eed36d01de13f83a8abdc13e93c21883a3a48273da83fa1c813e65e4655babcf`.
There is no recompilation and no server binary replacement. The existence of
the IO64 source change on this development branch does not make this entry use
that Runtime or daemon: the original binaries are pinned and verified.

Run `run --quiet-window-confirmed --accept-nonzero-baseline` as the ordinary
user, then paste the printed `COW4_ORIGINAL_256_RECHECK_ROOT` literal block into
the same host's root terminal within 600 seconds. Keep both terminals open; no
`done` input. `status` reads this new receipt. Earlier receipts remain intact.

This entry keeps the same four templates, eight Guests, continuous replay,
60-second idle interval, two host-wide sync/drop1 operations, observer and
sampling routines. It additionally verifies both effective queue limits are
256 KiB for all bound rootfs and memory devices. The original server executable
hash/inode is checked before activation, while active, and after restoration.
Only the original daemon path in the configuration is temporarily redirected
to the original observation build; the exact original configuration is restored.

Success is `COW4_ORIGINAL_256_RECHECK_MEASURED_GUESTS_RELEASED_RESTORED` and
requires complete observation coverage, device checks, Guest release and
restoration. Seven local admission/identity/device tests passed; they do not
substitute for the forthcoming target execution. Compare all three runs while
retaining background activity and cache-reclaim differences as potential
confounders; this repeat alone does not guarantee a noise-free machine.
