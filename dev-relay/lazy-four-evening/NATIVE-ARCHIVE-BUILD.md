# Native pmem archive Runtime candidate

Core commit: `7120140170924e239496886a3eac765f0b728080`.

`A_build_native_archive_v1.py` defaults to a plan. `--run` requires the previously prepared ordinary-user ARM64 build environment on node A. It verifies the existing export helper, frozen Cargo lock and successful earlier dependency receipt, then creates a new `builds/native-archive-release-v1` directory. It runs eight actual archive/manifest file tests and the provider Python suite, builds only the new Runtime server offline, and writes an immutable artifact/hash receipt. It never starts a Guest, calls the SDK, deploys services, rebuilds images or replaces an installed binary.

Each build phase inherits the reviewed 30-minute deadline, 20-second progress, full bounded log and owned-process-group interruption handling. A failed or interrupted directory is preserved; do not rerun into it. `return.json` records success or failure; success is `NATIVE_ARCHIVE_RUNTIME_BUILT_TESTED_NOT_DEPLOYED`. The copied candidate is `artifacts/server`; provider source remains under the extracted source tree. Existing FC, verifier, daemon and CLI are unaffected. Native deployment must separately verify those versions and opt into archived v3 bindings.

The source packet excludes the repository's AGENTS symlink and contains the complete published source tree plus a dependency-locked file test harness. It contains no target reports, credentials, workload payload or images. Local validation: exact tree/payload checks, four packet tests, ARM64 full project `cargo check --tests`, 22 actual-source file/binding tests on Windows, 44 Python tests. The harness uses a minimal snapshot lease type, so these tests do not establish Linux repository, UB, KVM or Guest lifecycle acceptance.

This candidate adds snapshot-owned persistent base images, hash-checked POSIX/OSS hydration, retained source descriptors and cache leases across Fork/rebinding. Legacy snapshots keep their external-source requirement. `bind-retained-snapshot` prepares an explicit republish catalog; it does not automatically republish UB objects. Per-snapshot archives consume storage and may populate Host cache. They are not Guest RAM copies and must not be counted as memory savings. True cross-node memfile private CoW and automatic UB republish are still absent.

This build is independent of rootfs retry commit `719ea4c8c65a7752d87d536cc00a0968aa89598d`, which uses the existing Runtime. Do not label that retry as native-pmem archive validation. No target machine was accessed during preparation.
