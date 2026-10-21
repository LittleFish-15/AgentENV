# Native CoW experimental relay

These field scripts intentionally use the reviewed lab layout. Core/main are
unchanged. No credentials, active UB object manifest, captured measurements,
private workload or binaries are included.

Latest: `A_futex265_policy_guest_v5.py`. Run as the ordinary experiment user with
`--run`, then review and paste its printed root block. It verifies the actual v4
SIGSYS report (AArch64 VMM futex 98, operation 265 and bitset MATCH_ANY, all children reaped), retains the
getpid and tgkill fixes, and adds only VMM futex with argument 1 equal to 265 and argument 5 equal to 4294967295. The strict trap
default and every other rule remain unchanged. It reuses the existing compiler,
FC binary and UB publisher. No SDK allocation, service restart or full build.
It records bounded serial/stderr tails in the Guest result. Preparation is not a
Guest pass; no cross-node CoW or memory benefit is asserted.

SHA256: `d88bdc1f2578bb5f367030e1ca7352c098016a223f6259aff2399168d067563b`

The earlier getpid-v3 runner remains for provenance; do not rerun completed cases.
