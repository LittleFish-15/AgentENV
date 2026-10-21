# Native CoW experimental relay

Latest A service preparation: A_prepare_native_service_builtin_v2.py prepare
with explicit core, builtin-FC and runtime-tools receipts. The entry requires
the actual ef4c6e1b FC build and its successful Guest run without external
seccomp/tracer. It copies the already built Runtime executables and verified
FC/tools/dependencies to a new isolated deployment on port 18082. Old original
and modified services must stay healthy and keep the same identities.

Preparation does not start a service or Guest and calls no SDK. The printed
root block submits only the new native Runtime unit as the ordinary account
with process-scoped KVM/aenv groups, CAP_SYS_ADMIN/CAP_NET_ADMIN and private
network/mount namespaces. Those capabilities are powerful; the block makes
them explicit. LimitMEMLOCK=2 GiB applies only to the new unit, not the Host or
old services. After starting it, run the printed ordinary-account health entry.

Without an explicitly validated rootfs binding this is service readiness with
native sharing disabled. Do not claim UB rootfs activation, complete AgentENV
integration, snapshot/Fork support, memfile private CoW or net memory savings
from health alone. The synthetic test image must not impersonate a business
source image. Core/main are unchanged by this experiment script publication.
No credentials, active object manifests, measured results or binaries included.

SHA256: 79a166ff9b8d750b807289600c60a1f96ce96b1ca2510ea15ca5fc60815b83d9
