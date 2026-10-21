# Native CoW experimental relay

Latest B entry: B_native_dax_guest_v4.py --prepare-root, then review and paste
its printed root block. Reuse A's already-transferred FC and filter. The prior
v3 run stopped before SDK calls because it wrongly required the retired control
socket pathname to disappear. Production teardown closes that listener without
unlinking the control socket file; the data socket is unlinked.

V4 retains both coordination locks and successful v2 release checks, requires
the old data socket to be absent, and allows only an unchanged, owned 0600
control socket whose connect returns ECONNREFUSED. Live endpoints, permission
errors and changed identities stop execution. No old socket or receipt is
removed. New v4 state is separate; any v3 state/pending is refused.

One B Guest reads A's existing base through UB/pmem/DAX and checks private upper
copy-up. Only after definitive Guest exit are B's mappings retired. Unresolved
Guest lifecycles preserve the provider. Keep A publisher alive throughout.
No existing daemon restart, global permissions, owner deletion or UB allocation.
This is not full AgentENV integration, simultaneous A/B Guest acceptance,
memfile private CoW or global memory savings. Active manifest stays local to B.
Core/main remain unchanged; previous experiment scripts remain for evidence.

SHA256: ddbe0102021c03cc71c74aa6dec263928c8cc4021f9c931886d8e713216a1ef5
