# Native CoW experimental relay

Latest: A_compact_real_rootfs_v1.py --run, ordinary node-A user.

Requires the successful real-rootfs export receipt. Creates a new sparse private
copy and verifies full source/copy SHA256 before filesystem changes. The original
64 GiB image, original layered sources, snapshots and services are preserved.

Uses installed e2fsck, resize2fs and readonly debugfs. Performs a full readonly
filesystem check and extracts three fixed sample files before changes. Records a
clean full check on the new copy only, then uses resize2fs -M without forced flags.
After shrinking, requires clean fsck, preserved filesystem UUID/allocated inode
count, and unchanged hashes for two PyPika source files and /etc/passwd.
Only after validated filesystem geometry may the container length be adjusted,
with padding to 2 MiB alignment and another full readonly check. This is not blind
truncation based on sparse allocation. Final image SHA256 is recorded.

This checks filesystem consistency and three sample files; it does not establish
complete file-tree equivalence, Guest workload acceptance, or DAX support by itself.
Requires 12 GiB initial free disk, 4 GiB free-space floor, 4 GiB sparse-copy data
write budget and a compacted filesystem no larger than 4 GiB. Guards are not a
filesystem quota. Partial copies and reports are retained on failure.

No root, mount, ublk, Guest, SDK allocation, publication, service changes or global
cache flushing. No recompile. Core/main unchanged. Next: size-aware UB publication
and actual Guest workload validation. No net memory savings are claimed here.

SHA256: 0e75934e9ea96dfa31a30fca4196fd17e8c7305d7cfbff965052e37df100a17b
