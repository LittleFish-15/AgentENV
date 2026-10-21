# Native CoW experimental relay

Latest A entry: A_build_builtin_policy_v1.py --run. It copies the reviewed FC
source into a new build directory, adds the strict GNU policy and fail-closed
build-script change from clean core commit 56005a7, then builds offline using
existing frozen inputs and the existing incremental target cache. The old
staged executable and original source are verified unchanged. No SDK call or
service deployment is made during the build. Core/main are not changed here.

The build must emit the same 2810-byte BPF as the externally supplied policy
already validated on the nodes, and those bytes must be present in the new
executable. On success it prints a reviewed cap0 KVM Guest block with neither
an external seccomp filter nor a tracer. This verifies the new binary's normal
built-in-policy path before deployment. Build completion alone is not a Guest
pass, Runtime deployment, snapshot/Fork support or memfile private CoW.

Keep the existing A UB publisher alive. Do not rerun an existing build directory;
inspect its return.json/build.log or use its saved root-review.txt as appropriate.
Earlier concurrent and component measurement scripts remain for provenance.
No credentials, active UB manifests, measured data or binaries are published.

SHA256: 5ebedb9f5a06b580a482a12f9ae1a2f60a51df5e7c8c67aae26a48c5c4792308
