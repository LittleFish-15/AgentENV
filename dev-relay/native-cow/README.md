# Native CoW experimental relay

Latest: A_finish_compact_rootfs_v2.py --run, ordinary node A.

Resume only the known v1 successful resize stopped at the UUID/inode guard.
Preserve original and prior receipt. No repeated resize, 64 GiB copy or hash.
Record actual geometry changes, run full readonly fsck, compare three workload
samples against original. Add a DAX marker only to the private resized copy if
absent, verify readback, fsck, align the validated filesystem container to 2 MiB,
fsck again and hash the final image. No SDK, Guest, mount or service change.
This is filesystem/sample validation, not full-tree or Guest acceptance.

SHA256: ab88deb49a6bc3326496745bfc24935829cf9541a720d865b6623abf83c26cab
