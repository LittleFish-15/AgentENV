# Full candidate native build with broker retirement confirmation

Entry: `A_build_full_ub_candidate_v3.py` (393647 bytes).
SHA256: `ab3e00c085e61a8d3ca3c5b11c5982d6996590cdacdb47bcd888bb1896d6b890`.
Core GitHub commit: `509e1fe7891b614679f6197377b966ca7b1099fa`.
Local source commit: `27b770f0b1b259d3492292402b1038dc451d71e4`.
Source tree: `f8a139dca1cfe8fa8d3f0cb142c0172da18ff33e`.

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
ownership and Unix directory-retention tests. Full-set metadata tests remain; the unmodified full payload experiment is not rerun.
Sources reconstruct as 884 ordinary files with 14 embedded changes.
AGENTS.md Git symlink metadata is not materialized; its CLAUDE.md target is included.
The isolated output directory is `/home/jwk/agent/builds/full-ub-runtime-candidate-v3`.
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
