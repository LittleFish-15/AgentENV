# Native CoW experimental relay

Latest sequence: run A_transfer_verified_fc_v1.py --run as the ordinary account
on A, then B_native_dax_guest_v3.py --prepare-root as the ordinary account on B.
Review and paste the printed B root block. The assistant does not connect to
either node. The user-run transfer uses normal SSH authentication and host-key
verification and transfers only the hash-pinned FC and BPF from A. It refuses
different or incomplete existing destination files, and changes no services.

B verifies the actual prior v2 import/release evidence and locks. It imports
the same A base read-only, starts one 256 MiB DAX selftest Guest using the pinned
FC/filter, and retires the import only after the Guest lease is safe to release.
If the Guest lifecycle is unresolved, the provider remains alive. Keep A's
publisher alive and do not use an older B release receipt to retire A while a
new B run is active. No allocation, owner deletion, existing service restart,
permanent account-group change or Host permission change is performed.

This is a standalone B mechanism test. It does not claim simultaneous A/B
Guests, full AgentENV integration, memfile private CoW or global memory savings.
The active object manifest stays in B's existing local experiment directory.
No credentials, private benchmark, measured data or production binaries are
published. Lab metadata is within the user's explicitly approved disclosure
scope. Core/main remain unchanged. Earlier scripts remain for provenance.
