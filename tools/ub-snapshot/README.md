# Experimental UB snapshot and rootfs lowers

Baseline: `ae9c62693839ce7effa2b45df31c0039ae4f9fbc`, workspace 0.2.2.
See [source review and acceptance](../../docs/src/internals/ub-shared-layers-review.md).
The first implementation reuses immutable **stored layer bytes** through UB and
keeps each node's original local CoW. It includes memory and rootfs lowers.
Guest RAM physical Base sharing, zero-copy and a cluster-Fork scheduler remain
separate work. This experimental branch requires target acceptance before use.

## Preferred relay: one readable Python script

For manual relay, generate `ub_layer_once.py` with
`python3 -I -B tools/ub-snapshot/make_single_file.py OUTPUT_PATH`.
It embeds the actual bridge/broker/controller as uncompressed readable source;
there is no ZIP, downloader or third-party Python dependency. Copy only this file
to `/home/jwk/agent/ub_layer_once.py` on both original nodes. On A as ordinary jwk:

```bash
cd /home/jwk/agent
python3 -I -B ub_layer_once.py owner node-a
```

Run the complete peer command printed by A on B. B invokes the same single file,
prepares its own sources, and imports the same object. After B fully exits, type
`done` on A. Success/cleanup criteria are the E2 criteria below. The entrypoint
also accepts the same `--format/--probe` and explicit owner `cleanup --peer-stopped`
options when their prerequisites hold.

Generated helpers are stored under `/home/jwk/agent/relay/ub-layer-single-v1`;
byte-equivalent sources can be reused, different/incomplete/unknown files are
preserved and rejected. Original smoke locks and pending receipts are shared, so
an unresolved older ZIP run still blocks new random objects. Neither a directory
presence check nor this packaging change clears an unresolved SDK result. BOM
and CRLF text transfer are supported. Revision directories must change if a later
release changes embedded code; do not overwrite an existing helper directory.

The single-file package/entrypoint checks are local only; target SDK linking,
mapping and all Guest acceptance remain pending. The older ZIP instructions below
remain for already delivered packages; the single-file entry supersedes their
manual unpack step.

## Runtime path

```text
committed stored bytes -> public SDK NC object -> readonly local broker
 -> UbLayerFile -> original tar/ZFile/LSMT -> local ublk
 -> original File RAM restore / private rootfs upper
```

The broker maps through the installed public `ubs_mem.h` API. It neither exports
an internal FD nor maps UB into Firecracker. The client binds object, generation,
stored digest, valid file length and mapping length. Requests are bounded to
1MiB; responses must be complete. A client read allocates at most 64MiB. Up to
64 mapped objects and 128 local connections are accepted. Clients in the same
process share a generation-specific connection per layer. Live connections hold
reader leases, including idle readers and in-flight requests.

Publishers verify full stored bytes, remove writable maps, verify readonly maps,
then advertise Ready. Importers perform no allocation/deletion. The SDK does not
provide a global immutable seal here: no external authorized writer may mutate
published objects. Only NC flags6 are supported. Each object includes a 4096-byte
identity header; the SDK length rounds `(stored length + header)` up to 4MiB.
Backing coverage can round further. The coverage inspection threshold is checked
**after creation**, not a pre-allocation quota or an exclusive physical increment.

Opt in independently in the **new experimental server's environment**:

```bash
export AENV_UB_MEMORY_REPLICAS=/home/jwk/agent/ub-layers-a/replicas.json
export AENV_UB_ROOTFS_REPLICAS=/home/jwk/agent/ub-layers-a/replicas.json
```

Set the node B paths to its local import directory. The index may contain the
union of the two layer kinds. Every selected lower must have the same digest and
stored length in a Ready index; incomplete selection fails. The source config is
preserved. Binding creates an immutable `.ub-view-<content-hash>.json`, which also
prevents a device pool from reusing an older object's generation. Unset both
variables to retain the original path without loading an SDK library. Rootfs
writable uppers are still created by the original per-instance runtime machinery.
Extra drives, writable volumes and tools are not implicitly added to UB.

Required UB takes precedence even if a local copy exists. There is no automatic
fallback. `--allow-repository-fallback` explicitly permits a **local durable
file** with matching full digest/size. The client pins the verified open file,
rereads the complete failed range, and logs `resolved_source=repository` on
degradation. Missing/mismatched local fallback files fail. Registry fallback is
not implemented. An acceptance run must use required UB and observe broker reads.

When a consumer commits a child snapshot, immutable UB ancestors remain outside
runtime-suffix compaction. Durable publication exports and hashes their stored
bytes before recording the child's complete layer chain (POSIX and OSS paths).
This happens after capture. UB is a disposable replica, never the only durable
truth. A new publication can use `--reuse-index` to borrow unchanged ancestor
objects and allocate only new layers. A borrower never gains deletion ownership.
OSS compression may change a newly committed stored identity; use its returned
descriptor when planning the next publication.

## Local checks and their limits

Run without an SDK, VM, existing service or capabilities:

```bash
python3 -I -B tools/ub-snapshot/test_broker.py
python3 -I -B tools/ub-snapshot/test_smoke.py
rustc --edition 2021 tools/ub-snapshot/protocol_client_test.rs -o /home/jwk/agent/ub-protocol-client
AENV_UB_PROTOCOL_CLIENT=/home/jwk/agent/ub-protocol-client python3 -I -B tools/ub-snapshot/test_broker.py
cargo test --frozen -p overlaybd --lib backend::ub
cargo test --frozen -p overlaybd --lib config::ub_tests
cargo test --frozen -p agentenv --lib split_runtime_suffix_keeps_ub_ancestor_without_a_local_duplicate
```

Use the existing offline Cargo source configuration for Cargo commands. The
cross-language test explicitly skips if its compiled Rust client is absent.
The Python SDK double checks ownership/control logic; it cannot prove hardware
mapping behavior. Linux-only file/fallback tests need Linux execution. Cross
compilation checks types, not target runtime behavior.

## E2: first target test, one 4MiB object

Use the separately delivered `UB-layer-sdk-smoke-v1.zip` on the original
node-a/server1 and node-b/agent1. Ordinary jwk UID1204/GID1205, zero capabilities,
working directory `/home/jwk/agent/ub-layer-sdk-smoke-v1`. It contains this broker,
bridge and `sdk_smoke.py`; no tools/dependencies are installed. See the included
Chinese execution sheet for transfer/unpack commands.

On **A**, keep the terminal open:

```bash
cd /home/jwk/agent/ub-layer-sdk-smoke-v1
/usr/bin/python3 -I -B sdk_smoke.py owner node-a
```

After `UB_LAYER_SDK_OWNER_READY`, run the **complete peer command printed by A**
in B's jwk terminal. It imports exactly A's object and reads through B's broker;
it does not allocate. After B reports `UB_LAYER_SDK_PEER_COMPLETED` and its
process fully exits, return to A and type `done`. A must report
`UB_LAYER_SDK_OWNER_COMPLETED`, deletion/mapping/finalize acknowledgements.
Return both complete `BEGIN_RETURN_REPORT`/`END_RETURN_REPORT` sections.

Side effects: each node compiles a new small bridge and writes a report below
`/home/jwk/agent/relay/reports`; A creates at most one independent 4MiB logical NC
object containing a 1.5MiB payload; B allocates zero. No ublk/Guest is used.
Stop on failure; do not run as root, change ACLs, delete pending receipts or retry
with a different mode. A's explicit recovery, **only after B fully stops**, is:

```bash
cd /home/jwk/agent/ub-layer-sdk-smoke-v1
/usr/bin/python3 -I -B sdk_smoke.py cleanup node-a --peer-stopped
```

Cleanup requires a confirmed creation and matching generation/header/full hash;
an unknown creation remains unresolved. SDK busy/error also remains unresolved.
This test validates this new bridge/broker, not the already passed basic UB14
experiment, and not an AgentENV Guest.

## E3: real stored formats and private uppers

Build once on A, reusing existing offline inputs without changing them:

```bash
cd /home/jwk/agent/src/agentenv-ub-layers-v1
/usr/bin/python3 -I -B tools/ub-snapshot/build_offline.py
```

The script requires ordinary server1 jwk, the original lockfile, existing
standalone Rust/vendor pointers and at least 16GiB free space. It uses a new
report/build/cache/target directory, offline/frozen Cargo and two build jobs.
It runs full server/daemon checks, relevant non-privileged tests and builds four
artifacts. It never installs or launches services. Return its complete report on
success/failure. Copy its four binaries to B using the existing relay; do not
compile them again there. Keep the original deployed baseline binaries intact.

Copy the **reported** `ub_layer_probe` binary to this identical path on A and B:
`/home/jwk/agent/ub-layer-probe-v1/ub_layer_probe`. Create the new containing
directory as jwk; do not replace an existing binary. The E2 smoke directory and
its scripts stay at `/home/jwk/agent/ub-layer-sdk-smoke-v1`.

After E2 succeeds, the same controller runs each real format with one small
object and automatic fixture generation, local/remote broker reads, two private
uppers, durable child reopening, reports and cleanup. B does not need duplicate
stored layer files. On **A/server1 as jwk**, run the following separately:

```bash
cd /home/jwk/agent/ub-layer-sdk-smoke-v1
/usr/bin/python3 -I -B sdk_smoke.py owner node-a --format raw --probe /home/jwk/agent/ub-layer-probe-v1/ub_layer_probe
```

At `UB_LAYER_FORMAT_OWNER_READY`, run the **complete current peer command printed
by A** on B/agent1 as jwk. It includes the exact object token, format and probe
path. B must return `UB_LAYER_FORMAT_PEER_COMPLETED` and fully exit. Then type
`done` on A; require `UB_LAYER_FORMAT_OWNER_COMPLETED`, nonzero broker read
counters, base re-verification, A one acknowledged deletion and B allocation zero.
Both nested format reports must have `two_private_uppers`, `base_unchanged` and
`durable_child_reopen_without_ub` equal to true. Return both complete reports.

After the raw owner process fully exits and cleanup succeeds, on **A**:

```bash
cd /home/jwk/agent/ub-layer-sdk-smoke-v1
/usr/bin/python3 -I -B sdk_smoke.py owner node-a --format tar --probe /home/jwk/agent/ub-layer-probe-v1/ub_layer_probe
```

Repeat the same B-current-command / B-fully-exits / A-`done` sequence. After the
tar owner fully exits and cleanup succeeds, on **A**:

```bash
cd /home/jwk/agent/ub-layer-sdk-smoke-v1
/usr/bin/python3 -I -B sdk_smoke.py owner node-a --format zfile --probe /home/jwk/agent/ub-layer-probe-v1/ub_layer_probe
```

Repeat the same sequence. Each format creates at most one 4MiB logical object;
all format files, independent uppers and exported ancestors stay in its own
report directory under `/home/jwk/agent/relay/reports`. They are retained for
audit. No service, ublk device or VM is created. The probe rejects an existing
output directory. Failure preserves its reports and unresolved owner identity;
use the E2 explicit owner cleanup only after all consumers fully stop. Do not
retry by removing a receipt or changing object names/modes.

For real committed snapshots, the lower-level `ub_layer_broker.py plan`,
`publish`, `import` and `cleanup` commands expose the same lifecycle. `plan`
accepts `--memory-image` / `--rootfs-image` and optional `--reuse-index`, creates
only its private work directory/lock, and prints all stored/rounded/new byte
counts without loading or calling the SDK. Use `--help` for explicit arguments;
the smoke sequence above is the bounded first acceptance path.

## E4/E5 and the deployment boundary

The original two-node baseline deployment is a separate workstream. Do not
replace its binaries, units, ports, data roots, cached configs or active devices.
The modified server needs its own reviewed launch configuration and namespace.
No new root/capability/device/group/service changes are included in these tools.

Before a real VM publication, run `plan` on its committed memory/rootfs configs;
record all selected stored bytes, rounded mapping totals and new allocations.
The 4MiB default deliberately rejects a larger snapshot. No automatic budget
increase is performed. B still needs the committed catalog/VM state and complete
disk/drive dependency metadata; the UB index alone is not a complete snapshot.
Provision this in the independent experiment repository, not an existing service.

Mandatory remaining acceptance: baseline File restore on A/B; required-UB memory
and rootfs restore with nonzero broker reads; RAM marker state retained solely in
a live guest process, disk markers at the same capture point; divergent first
and repeated writes with unchanged parent/sibling; recapture/reopen and ancestor
object reuse; deleting one child without breaking another; broker loss producing
an explicit error or verified full-range fallback; opt-out returning to baseline.
The original `aenv snapshot create ID --name NAME` and `aenv start -d NAME`
commands are node-local API clients, not automatic cross-node scheduling. Exact
VM commands depend on the baseline's validated offline template, new runtime
endpoint and repository transfer path. These prerequisites must be resolved from
the deployment result before an E5 run; no Guest result is inferred here.

Normal retirement: stop only experimental VMs/readers, retire B/importers and
wait for complete process exits, then retire owners. Stop on SDK busy or unknown
ownership; preserve receipts. There is no TTL-driven, forced or global cleanup.
