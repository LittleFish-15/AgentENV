# Read-only rejoin of retained native contents

When the publisher's Host has rebooted but an importer still retains the UB
object, restarting `role=publish` would allocate another object. Reusing the
importer's `readerId` would impersonate its lifecycle. Neither is recovery.

The service's explicit `role=rejoin`, `mode=pmem` path reuses the existing
`RawImages.imports`: initialize the SDK, map each exact object read-only, verify
the content, and hand off its existing region FDs. It never calls publication
or allocation. The publication's owner, replicas, generation and reader list
remain unchanged. Missing or unconfirmed maps do not trigger allocation.

The ordinary worker needs a SHA-pinned, root-owned permit below
`/home/jwk/root`, with root-owned non-writable parents. It binds the original
publication, the original publisher's machine, a different current boot,
a new local reader identity and the exact retained peer identity. The
coordinator must verify and retain that peer before issuing the permit. The
peer identity in a permit is not a live remote heartbeat; SDK MAP and content
verification remain necessary and can fail.

The rejoined process has **local-mappings-only** release authority. Its receipt
has scope `readonly-rejoin-local-release`; the old publisher's ordinary peer
receipt validator rejects it. It cannot replace the original reader's release
or authorize deletion of the global object. After attaching a Host pmem volume,
use the existing `hostPmemReleaseReceipt` guard: consumers exit, unmount,
confirm the local volume absent, close the lease, and only then retire the
rejoined SDK process. All original ownership and unresolved-operation records
remain historical evidence. Global deletion and ownership recovery need a
separate, complete coordinator decision after all local uses have exited.

This adds no kernel ABI and does not provide memfile private CoW. Tests of its
permit, service dispatch and release handling are local logic tests; successful
Linux SDK mapping, DAX reads and cross-node physical identity require actual
machine receipts.
