# Native CoW experimental relay

Field execution scripts live on this experimental branch; the core and main branches are unchanged. These scripts intentionally target a reviewed lab layout and are not portable production components. No credentials, active UB object manifest, captured measurements, private workload or binary is included.

A_getpid_policy_guest_v3.py is the unchanged reviewed field program. Its default prints a plan. An explicitly authorized capability-free KVM test process can use --run --execute-guest. It verifies actual syscall-172 evidence and adds only VMM getpid to a strict policy. It does not allocate UB, restart the provider or disable seccomp. It preserves previous experiment output.

SHA256: `b4053fafdd2e36c953c9d11c7aeae73cc28e8dec27dca90cf6a8b4c3c3321131`
