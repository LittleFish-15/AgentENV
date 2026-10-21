# Coordinated native Runtime preparation and recovery

Core source is pinned to `d3e61ea93495f1eff668934a003d4ca87c7cfa94`.
These entries do not claim that native RAM private CoW is implemented, that
services are deployed, or that native pmem snapshots passed hardware tests.

`A_prepare_release_v4.py --run` prepares the A-side compact executable rootfs
image and builds the five coordinated binaries. Its report is under
`/home/jwk/agent/builds/native-release-v4/return.json`.

`native_release_bundle.py pack` accepts that report and the existing successful
runtime ext4 tools preparation receipt. It writes one new archive with the five
binaries, tools image and filtered receipts. It does not copy a live database,
API credentials, Guest rootfs layers or UB publications. The caller transfers
the archive and its SHA256. `receive` requires the exact SHA256 and a fresh
destination; it verifies the archive and each member before returning receipt
paths. It executes no archive content and preserves partial outputs on failure.

`prepare_native_service_v4.py prepare --node node-a|node-b` consumes the
coordinated build receipt, `--tools-report`, and optionally `--tools-image` when
the received bundle relocated the tools image. Choose exactly one of:

- `--rootfs-binding PATH --binding-sha256 SHA256`: a v3 ext4 binding whose
  verifier path and both binary hashes match the installed coordinated release;
- `--ordinary-only`: explicit control service without a UB rootfs binding.

Preparation creates a distinct deployment and prints a scoped root activation
block. It does not execute systemd commands. The existing namespace, capability
and proxy launcher is reused. It preserves the original Runtime, earlier
experimental Runtimes, `ubsmd.service` and `ubse.service`.

The new units are `jwk-aenv-native-d3e61ea-node-a.service` and
`jwk-aenv-native-d3e61ea-node-b.service`, with node-local deployment directory
`/home/jwk/agent/deployments/agentenv-native-d3e61ea`. The assigned loopback port
is selected from 18082 through 18089 and recorded in the immutable definition.
The preparation report is saved as `prepare.json` and includes the health
command. Health establishes service readiness, not Guest or CoW acceptance.

## Controlled rollback and reactivation

`prepare_native_service_v4.py rollback-plan --node NODE` prints a root block;
it performs no service stop itself. The block acquires the experiment lock,
checks exact input hashes, boot, service and proxy process identities, requires
a quiescent experiment journal and an empty running/paused sandbox inventory,
then stops only the new Runtime unit. It stops the host proxy through a pidfd,
which cannot select a different process after PID reuse. It preserves all
snapshot files, the installation and UB publications, and verifies older
services are unchanged. A failed check stops the rollback without forcibly
clearing unknown resources. A timeout after requesting the stop is reported as
uncertain; no blind retry or forced proxy kill follows.

After a completed stop, `activation-plan --node NODE` validates the retained
installation and prints a new activation block using current older-service
identities. It requires the transient new unit to be absent and the same boot.
Reactivation across a host reboot is not implemented by this entry.

Every future batch controller using these services must hold `cohort.lock`
through its mutating operation sequence and update `cohort-state.json` before
issuing requests. The journal starts as:

```json
{"version":1,"phase":"prepared","openRequests":[],"sandboxIds":[],"outcomeUncertain":false}
```

An active or uncertain batch must not be marked quiescent just because a client
timed out. Rollback refuses pending requests or retained sandbox IDs.

## Still outstanding

The release bundle deliberately contains no workload rootfs or live UB manifest.
The immutable input transport and real-rootfs provider transition entries are
described in ROOTFS_INPUTS.md and GENERATION.md. The bounded local
capture/restore/Fork batch, public workload and explicit-gap report are described
in COHORT.md. They are implemented and fixture-tested, not target-executed.
ROLLOUT.md describes the new A-side bootstrap candidate and its two scoped root
blocks. Coordinated post-workload holding now keeps both node cohorts alive
through their samples. The samples remain non-atomic. A privileged sampling
fallback and Host lower access observer integration are still absent; ordinary
permission failures remain NA. Do not label these
entries as a fully accepted cross-node RAM/rootfs CoW implementation.

Local validation: 6 deployment contract checks, 7 generated rollback checks
against an in-memory OS model, and 5 bundle integrity/layout tests passed. They
do not execute Linux systemd, KVM, UB, real signal delivery or target filesystems.
