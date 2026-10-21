# UB immutable image provider

This is an optional Linux runtime component. It performs no service installation,
privilege changes, Guest creation or dependency download. Run as the same ordinary
UID as AgentENV, with zero process capabilities. The SDK must already work for
that account. Use a new private generation directory for each publication/import.

Build against the installed **public** SDK headers and library:

```sh
c++ -std=c++17 -O2 -fPIC -shared -pthread -Wall -Wextra -Werror \
  -I "$SDK_INCLUDE" sdk_adapter.cpp -L "$SDK_LIB" -lubsm_sdk \
  -Wl,-z,relro,-z,now -o libaenv-ub.so
python3 -m pip install --no-deps .
```

The configured adapter hash is the SHA256 of this built library, including the
`sha256:` prefix. The ABI is version 3, with generic object names and an explicit
existing region. A different ABI is refused before SDK initialization. The
underlying SDK configuration/dependencies are an operator responsibility.

## Stored-layer publisher

```json
{
  "version": 1,
  "mode": "stored",
  "role": "publish",
  "workDir": "/var/lib/agentenv/ub/generation-a",
  "adapter": "/opt/agentenv/lib/libaenv-ub.so",
  "adapterSha256": "sha256:<actual-built-library-hash>",
  "region": "default",
  "logicalBudgetBytes": 16777216,
  "maxCoverageBytes": 536870912,
  "readers": ["reader-b"],
  "sourceRoot": "/var/lib/agentenv/snapshots",
  "images": ["/var/lib/agentenv/snapshots/memory.json", "/var/lib/agentenv/snapshots/rootfs.json"]
}
```

Replace the example limits with the measured aligned input budget. These are
logical and **post-map inspection** limits, not service-enforced physical quotas.
Index metadata validation does not read every source byte; publication does.

```sh
aenv-ub-provider serve publisher.json          # validate only, no SDK
aenv-ub-provider serve publisher.json --run    # keep running while used
```

Only immutable committed lowers are published. Mutable uppers remain private.
`replicas.json` is portable metadata. `runtime-index.json` is node-local and is
the stored-layer AgentENV hint. The broker copies bounded chunks into its local
consumers; it does not promise direct Guest physical sharing.

## Import on another node

Transfer only `replicas.json` through an approved transport. The import config
uses the same common fields and budgets, `role: "import"`, `readerId: "reader-b"`,
and `manifest` pointing to the received file. Omit publisher-only fields
`readers`, `sourceRoot`, `images` and `catalog`. Set the importer node's work and
adapter paths. The mode must match. The same serve commands apply. Import only
maps and verifies the existing UB objects; it never allocates or deletes them.

## Native pmem publisher

Use `mode: "pmem"`, replacing `sourceRoot`/`images` with `catalog`. Prepare the
catalog and rootfs binding from trusted, prebuilt, uncompressed, 2MiB-padded
EROFS or ext4 image files in bottom-to-top order:

```sh
aenv-ub-provider bind-rootfs --source ROOTFS_IMAGE_JSON \
  --image BASE_EROFS --socket NEW_GENERATION_DIR/data.sock \
  --max-bytes EXPOSED_BYTES --device-runtime RUNTIME_JSON --output NEW_BINDING_DIR
```

The runtime JSON contains `verifier`, `verifierSha256`, `firecrackerSha256` and
`verificationTimeoutSecs` (1..600). Both SHA256s include `sha256:`. It must name
the actual built verifier and patched FC. `image-catalog.json` is publisher input;
`binding.json` is the AgentENV rootfs binding. The importer requires only the
portable replica manifest plus a relocated binding, without copying image files:

```sh
aenv-ub-provider relocate-rootfs --binding PUBLISHER_BINDING \
  --socket IMPORT_GENERATION_DIR/data.sock --device-runtime LOCAL_RUNTIME_JSON \
  --output NEW_IMPORT_BINDING_DIR
```

`bind-rootfs --lower-filesystem ext4` explicitly selects immutable ext4 lowers.
Add `--snapshot-references` only with the matching version-3 Runtime/FC to enable
content-based snapshot rebinding. Relocation preserves version 3 and content
identity while replacing node-local sockets and binary pins. Immutable base
images and UB publications must remain externally retained for the lifetime of
referencing snapshots; this option does not provide distributed garbage
collection, repository backups, or native Guest RAM private CoW.
Version-3 images must also contain the static executable `/.aenv-dax-exec`
(mode 0555), built from `components/firecracker-native-pmem/guest-exec-probe.S`
for the Guest architecture before sealing/publishing the image. The Runtime
checks that this file remains DAX-backed and executes it, requiring exit 73,
on both cold boot and restore. This checks instruction fetch from the common
lower rather than execution from the ordinary tools drive. A successful
data-read probe alone cannot establish this property. Do not copy the probe to
the private upper as a workaround: the DAX check must apply to the executed file.
The default and omitted legacy `lowerFilesystem` field select EROFS. A binding
uses one filesystem type for all its lowers; relocation preserves that choice.
Prepare ext4 with 4KiB blocks, no inline data and no journal requiring replay.
The Guest mounts it with `ro,noload,dax=always`, so it never replays a journal or
writes the common base. Both filesystems must pass the same actual lower and
OverlayFS file-DAX checks; unsupported DAX fails the launch without fallback.

Images start at device offset zero. No stored-layer header is present. A raw
image may span up to 32 exported readonly SDK backing units. Their complete
ordered FD/length list is passed with wire protocol version 2; partial handoff
and truncated ancillary data are refused. Neither this component
nor readonly device mmap success proves KVM, Guest DAX, writable RAM CoW or net
memory savings. Native pmem explicitly rejects `privateCow: true` acquisitions.

## Retirement and failure

First freeze new imports and stop all Guest/readers for the generation. Retire
each importer only after its local inherited leases have closed:

```sh
aenv-ub-provider retire IMPORT_GENERATION_DIR
```

Transfer its `release.json` to the trusted publisher coordinator. After all
configured readers have released, retire the publisher with each exact receipt:

```sh
aenv-ub-provider retire PUBLISH_GENERATION_DIR --peer-receipt IMPORT_RELEASE_JSON
```

Receipts bind the owner generation, manifest hash and distinct reader identity.
They are trusted coordinator inputs, not an automatic distributed consensus or
failure detector. The coordinator must enforce one active importer per reader
identity. Unknown readers or revived imports invalidate retirement authorization.
Keep the provider running until the explicit retirement succeeds. Any live local
Guest/inherited child lease refuses retirement.

A disconnected control client does not authorize or undo resource operations.
Failure to deliver a refusal keeps the owner serving. Once cleanup and its
release journal/receipt have completed, failure to deliver the completion reply
keeps that durable released state. Reconcile the journal and exact release
receipt instead of repeating retirement after a lost reply. A cleanup failure
still records an unresolved state and does not issue a release receipt.

The owner journal is fsynced before each allocation; unknown allocation outcomes
are preserved without retrying a new name. Interruptions retain published UB
objects for reconciliation, including when a process dies. Never remove a failed
journal and blindly rerun. There is no automatic crash reclamation, SDK quota
increase, service restart or deletion of previously existing objects.

See [the implementation boundary](../../docs/src/internals/cross-node-cow.md)
before deploying or interpreting results.
