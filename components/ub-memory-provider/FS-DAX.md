# Existing FS-DAX publication adapter

This adapter consumes already published, immutable, readonly FS-DAX files. It
does not implement a UB-to-pmem device, allocate or free UB memory, modify a
kernel, mount/format a filesystem, or establish cross-node physical identity.
Use it only with a platform-supported presenter and an explicit lifetime
contract. A shared hash or filesystem UUID alone is insufficient evidence.

## Path and ownership

```text
platform-owned immutable UB publication
  -> supported pmem/DAX presentation on each host
  -> readonly FS-DAX files (active S_DAX, not raw /dev/dax)
       -> RAM: MAP_PRIVATE -> per-Guest private pages on write
       -> rootfs: FC readonly pmem -> Guest DAX lower + private upper
```

Both consumers retain open-file and connection leases through verifier and FC
exit. These are local leases. The platform owner must retain the underlying UB
publication until consumers on **all nodes** exit. Killing this Python process
does not establish remote release and must not trigger external deallocation.
Neither readonly permissions nor a readonly mount stop a privileged external
writer or a second writable mount; the publisher must guarantee immutability.

The provider validates metadata without reading the entire image. Runtime
checks the received FD again. A pinned, non-root, zero-capability child hashes
the complete mapping and verifies first/last-byte private-write isolation for
RAM. This touches the full base during preparation and is not a cold/lazy
measurement. Device faults and timeouts fail the acquisition; there is no copy
fallback. Host private-CoW verification is not KVM or Guest validation.

## Coordinated versions

Use a rebuilt Runtime, `aenv-native-fd-verify`, and FC with the current canonical
patch. Pin verifier and FC SHA256 values in `deviceRuntime`, including a bounded
`verificationTimeoutSecs`. Old binaries do not gain support from new JSON.

| Purpose | Binding | Provider protocol | Consumer |
| --- | --- | --- | --- |
| Existing CC file contract | RAM v1 | v1 | unchanged |
| Existing NC pmem | rootfs v2/v3 | v2 | unchanged |
| FS-DAX private RAM | RAM v2 + deviceRuntime | v3 | private file mapping |
| FS-DAX Guest rootfs | rootfs v4 + deviceRuntime | v3 | native descriptor v4 |

In the installed provider package, prepare rootfs metadata with the existing
`bind-rootfs` command plus `--fs-dax`. Optional `--retain-snapshot-bases` archives
exact bases; it does not retain a UB allocation. Use `bind-fsdax-memory` with
`--source`, `--image`, `--virtual-bytes`, `--socket`, `--device-runtime` and
`--output`. The RAM image must be the full linear snapshot memory, not a stored
OverlayBD/compressed layer. Both commands produce `binding.json` and
`image-catalog.json`; creating metadata is not publication or hardware validation.

Serve each catalog as an ordinary user:

```sh
python3 -m aenv_ub_provider.fsdax --catalog "$CATALOG" --socket "$SOCKET" --max-bytes "$LIMIT"
```

All variables denote explicitly selected local inputs. The socket parent must
already be private and owned by the Runtime user. An existing socket is preserved.
Catalogs contain at most eight objects. RAM and rootfs can use separate provider
sockets. The CLI only opens existing readonly files and creates its own socket;
it neither starts FC nor changes services. The output explicitly leaves physical
sharing unaccepted. `SIGINT`/`SIGTERM` closes admission, waits for inherited
consumer connections, and removes only its own socket. Stop Guests before the
provider; a blocked consumer must be investigated, not force-released.

Set `AENV_DIRECT_MEMORY_BINDING` to the RAM binding and
`AENV_DIRECT_ROOTFS_BINDING` to the rootfs binding/catalog in an isolated Runtime.
The existing rootfs Guest readiness check requires actual file DAX and executes
the immutable `/.aenv-dax-exec` probe (expected exit 73). Do not replace this with
an executable copied to RAM. The Guest image/kernel must already support the
pmem device and selected DAX filesystem.

## Snapshot, restore, and remaining gates

Snapshots save content hashes/length/order, never node FDs or socket paths.
Concurrent forks acquire independent leases and private RAM views. Restore must
explicitly rebind the same content. `relocate-rootfs` preserves version 4 and
requires matching local archive sources when used. `bind-retained-snapshot
--fs-dax` prepares v4 metadata only after the platform has republished those
archives to an existing readonly FS-DAX volume. It cannot silently republish to
ordinary files or NC SDK mappings. A missing base remains a restore error.

Before running workload comparisons, establish all three:

1. Both Guests' read mappings refer to one platform-attested UB base, without
   node-local base copies. A/B PFNs are not globally comparable by number.
2. A Guest's first write creates its private page, with peer and base unchanged;
   device-side writes must also private-CoW correctly.
3. Guest instruction fetch and page-table operations succeed from the intended
   backing. ARM64 KVM device-PFN restrictions can prevent this despite Host DAX.

None of these is inferred from unit tests, successful mapping, or file hashes.
Count the unique UB physical pool, node private pages, Guest RAM, upper data,
metadata/page tables, and provider overhead without double counting. Guest DAX
data is outside ordinary Guest RAM pagecache; application buffers still exist.
Missing physical accounting stays unknown, and this adapter promises no positive
memory or performance result.
