# Demand candidate native build with broker retirement confirmation

Entry: `A_build_demand_ub_runtime_v8.py` (475245 bytes).
SHA256: `860a127fbe4467e8c618f35001f1b15b4665ffeb6315d0c4fa1f14b8676d548d`.
Core GitHub commit: `2e3c2f75df2097d340ba16cbf7f813927c6f788c`.
Local source commit: `7677a06b6c6a1a20154b244e233d97662cabb3ea`.
Source tree: `a217808ecfd00b845e0e23eb4b4acea170586be1`.

This is an independent A-node ordinary-user build candidate, not deployment or
Guest acceptance. Use the default plan first. Only an explicit `--run` builds,
with the retained offline toolchain/package/native dependency caches and the
preserved full-v2 source. It requires the original build helper and its pinned
hash and checks source files, retained artifacts, zero capabilities and absence
of locally owned Guests before expensive stages. It must run outside comparison
measurement windows; local checks do not prove the peer or whole Host is idle.

The new provider change confirms that the broker accept thread actually exited
following the existing two-second join. A still-alive thread raises an error,
leaves the socket and closed admission intact, and prevents callers continuing
to SDK unmap/retirement. The three exact broker retirement tests must execute
and pass in the native build gate. Local tests use controlled thread doubles;
real Linux scheduling, SDK teardown and Guest exit have not been validated.

All previous build gates remain, including UB protocol/binding, failed-launch
ownership and Unix directory-retention tests. Demand cache, concurrency, residency, real O_DIRECT catalog/tail and Runtime demand-manifest tests remain.
Sources reconstruct as 886 ordinary files with 23 embedded changes.
AGENTS.md Git symlink metadata is not materialized; its CLAUDE.md target is included.
The isolated output directory is `/home/jwk/agent/builds/demand-ub-runtime-v8`.
Existing source/target/binaries/configuration, full UB objects and all older
entries remain. Rust sources are unchanged from the prior scoped-Clippy-clean
candidate; that result is inherited, not a new native Rust execution claim.

No SDK initialization/allocation, target deployment, Guest launch, kernel change,
port or cross-node transport is performed by this build entry. Failure preserves
progress, logs and partial outputs, with no automatic retry or deployment.
Success records actual produced hashes and still means built, not deployed.

Do not run every historical build version. This is the current candidate if a
new candidate build is needed. The already healthy deployed full version remains
`ff1efdd9a2598e19b84cc09b91c8bc1e10ab6254`; its acceptance entry's binary pins are
not changed to accept this candidate automatically. The first-template full
Guest demo does not depend on adopting this update or completing demand mode.

No target execution or new Guest/comparison result has been received for this
entry. Core/provider changes are independently fixed on the candidate branch;
private field results must never be published with the source.
