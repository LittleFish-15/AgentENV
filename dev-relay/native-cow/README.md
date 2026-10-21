# Native CoW experimental relay

Latest: native_pair_v1.py. Prepare on each node with --prepare node-a/node-b,
review and run each printed root block, then --observe from ordinary A while
both units run. The assistant never connects to the nodes; observation uses
the user's existing A-to-B SSH. No new network service is exposed.

One 256 MiB Guest per node reads the same A UB base and writes a node-specific
marker into its own overlay upper. Each checks the visible private marker,
unchanged lower probe and common-file SHA every five seconds for about 300s.
A causal observation sequence (A live, fresh B live reply, same A PID/start
still live) proves overlap without comparing clocks across machines. Final
acceptance also requires both normal Guest exits and B's real import release.
Old successful release evidence and generation locks remain required. An
unresolved Guest keeps its provider alive. Keep A's publisher alive throughout.

Preparation makes private tools copies and reuses already hash-pinned runners,
FC, policy, kernel and UB generation. Root blocks create only new cap0 test
units with process-scoped KVM/UBSMD groups. Existing services/host permissions
and previous test evidence remain untouched. No active manifest or measured
results are published. This is concurrent rootfs mechanism acceptance only,
not original-CoW comparison, memfile private CoW, complete AgentENV integration
or global net memory savings. Prior scripts are retained for provenance.

SHA256: 3464279312f9ffc59b8fa23a589c7e7c4ce321765fea8c2f9df2074c8e935875
