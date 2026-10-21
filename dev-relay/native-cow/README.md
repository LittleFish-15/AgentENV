# Native CoW experimental relay

Latest: A_export_real_rootfs_v1.py --run, ordinary node-A user.

Uses the existing pinned offline source archive and dependency cache. Overlays
three exact source files from core commit 734ba2e45216b1c80e2f35236fdd6916c9fef396
into a new build directory. Reuses Cargo target cache only; deployed binaries
and services remain unchanged. No network dependency installation.

Runs four sparse-output tests and the exact binary's three native tests through
a minimal harness (registry versions/checksums constrained to frozen Cargo.lock).
Builds only the rootfs exporter. Runs native Clippy when installed.

Finds the original PyPika source configuration and requires its 12 ordered layer
identities to match the captured 13-layer catalog prefix and original receipt.
Never silently drops the captured upper or treats it as the original OCI view.
Verifies every local committed layer hash, then exports the immutable logical
ext4 view directly through OverlayBD's local decoders, without ublk, mounts,
Guest, SDK, mutable upper, remote fallback, or service operations.

Requires 16 GiB free disk initially; data writes limited to 4 GiB, stored inputs
to 2 GiB, expected logical size exactly 64 GiB. Sparse filesystem support is
checked. These are data/headroom guards, not a filesystem quota. Full logical
hashing reads 64 GiB and is preparation cost, not a cold-cache experiment.
Partial outputs and old receipts are preserved; no automatic retry or cleanup.

Success is RAW_ROOTFS_EXPORTED, not UB publication or end-to-end CoW acceptance.
The sparse 64 GiB view needs separate verified filesystem compaction before any
UB allocation. Never truncate it to allocated bytes or count it as memory savings.

SHA256: 424ddd4cb3edc36f52b79081fedbfda67fed569578df0d7a323824611d94e048
