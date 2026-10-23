# DSec-style ordinary Host file sharing

This backend shares immutable rootfs data between Guests on one Host through
virtio-pmem and Guest filesystem DAX. It retains the Host page cache and avoids
redundant Guest file-data caches. Host FS-DAX, physical pmem and UB allocation are
not required. Separate Hosts still have separate page caches; this backend does
not claim cross-node physical sharing or Guest RAM private CoW.

Use `bind-rootfs --host-pagecache` with the normal source/image/socket/budget and
pinned runtime arguments. It emits **rootfs binding v5**, with portable content
references and optional `--retain-snapshot-bases`. `--host-pagecache` and
`--fs-dax` are mutually exclusive. `relocate-rootfs` preserves v5;
`bind-retained-snapshot --host-pagecache` binds retained ordinary files explicitly.

Serve the emitted image catalog as the Runtime user:

```sh
python3 -m aenv_ub_provider.hostfile --catalog "$CATALOG" --socket "$SOCKET" --max-bytes "$LIMIT"
```

The new wire protocol is version 4, source/cacheMode `host-pagecache`, and
privateCow false. RAM requests are rejected. Runtime and FC both validate an
exact-length readonly regular FD with observed inactive Host S_DAX. No NC device
or FS-DAX file is silently accepted under this contract. The child verifier
checks the complete content before FC startup; this preparation warms the source.

FC uses `aenv-pmem-fd:v5:SHA256_HEX:BYTES:hostfile:FD`, maps the ordinary file
shared/readonly, and saves a portable content reference. The device still needs
2MiB-aligned capacity. Restore acquires fresh local FDs/leases and verifies the
exact saved content/order/length. A missing or changed base fails. The matching
Runtime, verifier and FC must be rebuilt and their binary hashes pinned.

Guest DAX, merged-root DAX and the immutable executable readiness probe remain
mandatory. The same immutable inode/offset is required for Host page reuse;
separate files with equal hashes do not prove physical sharing. Writes use each
Guest's private OverlayFS upper. The trusted publisher must keep bases immutable
and retain them for live consumers and snapshots; a readonly FD alone cannot
prevent an unrelated Host writer. Existing provider admission, inherited lease,
drain and archive lifetime rules remain in effect.

Measure Host file pages once, Guest private RAM, upper and auxiliary costs without
adding overlapping process PSS/file-cache counters. Do not equate a lower Guest
Cached value or scoped-cgroup reduction with global physical savings. PMEM range
metadata, application buffers and private writes still consume memory. Compare
against the same original snapshot/trace, which may already share cached Guest
pages through local RAM CoW.
