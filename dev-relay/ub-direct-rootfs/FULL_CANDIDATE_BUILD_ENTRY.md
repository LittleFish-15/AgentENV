# Isolated full UB Runtime candidate build — not deployed

This entry builds full-mode candidate
`f329fd3ede3de70b0f1cc47fa8660d8d0041e192` (local
`81983cc4f413e57cc201200293408cb9576a72e0`), tree
`61f78d20beb9501e8bb48fa958f3f5c7560d8531`. It is distinct from the preserved
healthy full deployment `ff1efdd9` / local `25e445f`, and from the independent
demand candidate. It does not switch full mode to demand mode.

`A_build_full_ub_candidate_v1.py` is for A/server1 as ordinary jwk
UID1204/GID1205 with zero capabilities. Default invocation prints PLAN_ONLY.
Only explicit `--run` executes native unit tests and builds. No target run has
been started or reported by this entry. Exact bytes/hash are recorded in
`full-candidate-build-v1-packet.json`.

## What changes and what is retained

The candidate source adds the missing-only full-set metadata planner,
multi-broker lease regression tests, failed-launch handle retention and
unresolved required-UB work-directory preservation. It retains the full
rootfs backend and contains no demand Runtime manifest policy.

The entry reconstructs 883 regular source files, including nine changed/new
files, from the fixed retained full-v2 source plus SHA-checked embedded deltas.
The tracked `AGENTS.md` symlink is metadata and is not materialized by this
build-packet format; its `CLAUDE.md` target is included. This is a verified
build-source package, not a complete Git checkout with identical metadata.

All new source, Cargo target, temporary files, artifacts and phase logs use
`/home/jwk/agent/builds/full-ub-runtime-candidate-v1`. Existing full-v2 and all
demand directories are preserved. The retained native toolchain, offline Cargo
package cache and explicit RocksDB/Snappy/clang paths are reused; native
dependencies may still compile in the independent target. Require 24GiB free,
and refuse an existing candidate directory instead of deleting outputs.

The current full captured/deployed server and daemon hashes/identities are
checked before and after the build. Retained CLI, FC, kernel, tools and adapter
are verified and reused. No existing binary, configuration, provider object or
service is replaced. Checks cover A only, not a fresh observation of B.

## Native gates and output

1. Check host architecture, user/capabilities, retained full build provenance,
   package/tool paths, free space and absence of an owned local Guest. Repeat
   the Guest guard before expensive phases. This does not establish peer or
   whole-Host quietness; arrange builds outside comparison windows.
2. Run six new full-set metadata/composition tests. Do not rerun unchanged
   full-provider O_DIRECT or the previous real Host full-payload experiment.
3. Run actual OverlayBD wire/lease/binding tests, including the two-broker
   last-reader and partial-acquisition rollback cases. Missing expected test
   names or zero selected tests cannot count as passing.
4. Run four directory-retention tests (including Unix owner-only permissions),
   five failed-launch ownership tests, three existing launch-rollback tests
   and the existing delete-stop-retry test.
5. Build trace-enabled server and daemon; capture the exact produced artifacts
   before Cargo releases its lock. Save SHA256, lengths and capture provenance,
   and verify the preserved full artifacts again.

Phase intents/results are durable in `build-progress.json`; logs and
`return.json` remain under the new directory. Success is
`FULL_UB_CANDIDATE_CORE_BUILT_TESTED_NOT_DEPLOYED`; failure is
`STOPPED_FULL_UB_CANDIDATE_BUILD_PRESERVE_OUTPUTS`. Failures retain outputs and
do not automatically retry, deploy or clean resources.

No SDK initialize/allocation/import/deallocation, Guest creation, service or
kernel/module action, cache eviction or cross-node communication is performed.
The matching Runtime/daemon SHA256 values do not exist locally yet because the
native build has not run. Existing acceptance entries remain pinned to the
deployed full-v2 bytes and must not silently accept these candidate binaries.
A later candidate deployment needs its own matched identities and acceptance.

## Validation boundaries

Candidate ARM64 library/test code compiled locally. Three portable tests of
the actual production retention helper ran against local temporary files;
the Unix mode test and real FC/ublk failure behavior are still pending.
Whole Runtime Clippy still reports six inherited pmem-related lint errors.
Four packet tests verify exact source reconstruction, corruption rejection,
target isolation/native gate presence and the owned-Guest build guard.

The current healthy full small demo remains on its existing fixed entry and
receipts; this candidate build is not a prerequisite invented to rerun that
deployment. Nor does preparing it establish full Guest acceptance. The
four-template sixteen-Guest goal still needs coverage/capacity approval,
SDK coexistence policy and actual deployment/validation. Directory retention
does not implement crash-safe kernel ownership or automatic reconciliation.
