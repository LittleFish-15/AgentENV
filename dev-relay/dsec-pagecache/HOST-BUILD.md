# Coordinated DSec Host-file build

Run `A_build_dsec_hostfile_v1.py --run` as the ordinary experiment user on A.
It reuses the verified offline compiler/dependency caches and builds matching
Runtime, CLI, ublk daemon, native FD verifier and FC candidates. The core source
commit is embedded and all source payloads are hashed. No SDK call, Guest,
service replacement, image export, filesystem compaction or UB publication.

New outputs are under `/home/jwk/agent/builds/dsec-hostfile-release-v1`.
Existing images, deployed binaries and prior build receipts are retained.
An existing output directory is refused. The existing build cache is reused.
Each build phase has a bounded timeout/log size and emits progress; interruption
terminates that phase's owned process group through the existing reviewed helper.

Success is `DSEC_HOSTFILE_BINARIES_BUILT_TESTED_NOT_DEPLOYED`. Return the final
`BEGIN_NATIVE_RELEASE_REPORT` block. Deployment requires these resulting hashes;
this build is not an acceptance test or permission to call cross-node RAM shared.
The canonical strict ARM64 GNU policy is compiled and embedded, never disabled.
The two additional metadata rules are confined to duplicated backing descriptors.
