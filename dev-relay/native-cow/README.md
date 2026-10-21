# Native CoW experimental relay

These field scripts intentionally use the reviewed lab layout. Core/main are
unchanged. No credentials, active UB object manifest, captured measurements,
private workload or binaries are included.

Latest: `A_tgkill34_policy_guest_v4.py`. Run as the ordinary experiment user with
`--run`, then review and paste its printed root block. It verifies the actual v3
SIGSYS report (AArch64 VMM tgkill 131, signal 34, all children reaped), retains the
getpid fix, and adds only VMM tgkill with argument 2 equal to 34. The strict trap
default and every other rule remain unchanged. It reuses the existing compiler,
FC binary and UB publisher. No SDK allocation, service restart or full build.
It records bounded serial/stderr tails in the Guest result. Preparation is not a
Guest pass; no cross-node CoW or memory benefit is asserted.

SHA256: `c122688ed385a91b67f395a3a756d3c6b9d4aaa44fac77093698b708fab496b4`

The earlier getpid-v3 runner remains for provenance; do not rerun completed cases.
