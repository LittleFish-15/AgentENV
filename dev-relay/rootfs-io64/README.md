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
