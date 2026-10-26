# Required UB rootfs in the aenv Runtime

This path is ordinary Guest block I/O: snapshot/cold launch -> aenv Runtime ->
private rootfs ublk device -> OverlayBD `UbLayerFile` -> the same-UID UB broker.
It does not map UB into Guest RAM and does not implement memfile private CoW.

Configure `[snapshot].ub_rootfs_index` with an absolute node-local ready replica
index and `ub_rootfs_index_sha256` with its exact byte digest. A conflicting legacy
`AENV_UB_ROOTFS_REPLICAS` is an error. Memory binding remains independent. Legacy
environment-only deployments remain compatible but are not the strict deployment
contract for this experiment.

The snapshot resolver and cold/resumed Firecracker starts derive a generation-
specific rootfs config. Index bytes are read once, hashed and parsed from the same
buffer. Missing lowers, changed index content or local-fallback entries fail before
the Guest's ublk device is created. Private upper configuration is retained.

Before creating the rootfs device, `FirecrackerSandbox` acquires Runtime read
permits for every required lower. The local broker's peer UID is verified using
SO_PEERCRED; OPEN binds object, generation, digest and lengths. These permits are
separate from the daemon's own reader connections. The per-process weak registry
allows healthy sharing without making one Guest's exit close another's connection.
Read failures leave bounded process-lifetime incarnation tombstones, including
after the last file drops. Reopening the same failed incarnation does not silently
reconnect; explicit recovery or a new generation is necessary.

On normal stop, FC stops first, then the dedicated required-UB rootfs device is
deleted rather than returned to the warm pool, then Runtime read permits drop.
Deletion failure is returned and the Runtime retains its handle and permits.
Daemon delete drains its workers before dropping its backend and issuing DEL_DEV.
An uncertain/failed delete must be reconciled; it is not an automatic permission
to retire UB. Abnormal Runtime Drop does not prove daemon device deletion. The
broker and peer-release contract must continue to refuse generation retirement
while readers or unknown peer outcomes remain.

Build both `server` and `uvm-ublk-daemon` from this source revision. The FC binary
can be retained only after its hash/version is bound in the deployment receipt;
none of these Rust changes requires a Host kernel or OBMM replacement.

Validation instrumentation:

- Runtime lifecycle logs bind sandbox ID, derived config path and replica set.
- Broker OPEN logs include actual peer PID and immutable incarnation.
- `aenv::ub_read=debug` emits successful object/generation/offset/length records
  without payload; counters track successful UB reads/bytes and required errors.
- Build `overlaybd/rootfs-read-trace` for per-Guest ublk attribution. The ublk
  target supplies its actual image config path to IoCtx; content events preserve
  digest, byte range and `from_ub`, plus drained/error/drop accounting. Enable a
  bounded owned trace specification for the demo. Environment settings or aggregate
  broker bytes alone do not prove which Guest performed a read.

Rust tests exercise the real config binder and Unix broker client: pinned index
replacement/fallback rejection, retained upper, shared permit lifetime, short-read
poisoning and no reconnect after final reader drop. These are not Guest, UB hardware
or net-savings acceptance. The release must additionally pass native build/tests,
matching binary deployment, two live Guests, exact lower/read attribution, private
upper isolation, peer survival after one exit, and confirmed teardown. Full-template
Host Python read results are separate evidence and must not be relabeled as this
Runtime acceptance.


### Broker listener retirement confirmation

The stored-layer broker must confirm its accept thread has exited after the
bounded join before it can report retirement or remove its socket. A join
timeout leaves admission closed and raises an error, so the caller cannot
continue into SDK unmap or object retirement. Existing connection draining
and live read-lease checks remain required. This also applies to demand-backed
LayerView brokers. The check does not authorize retry or establish crash
recovery; native thread/SDK teardown and Guest lifecycle still need validation.
