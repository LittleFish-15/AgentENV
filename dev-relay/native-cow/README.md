# Native CoW experimental relay

A rootfs component comparison has its separate execution entry points. The
latest B_import_release_v2_github.py --prepare-root prints a reviewed transient
capability-free B unit with a process-scoped ubsmd supplementary group.
Its --run operation is only for that unit. The prior ordinary B process could
not traverse the local SDK IPC directory. No daemon restart, persistent group
change, chmod, ACL or host-network change is performed.

The importer verifies the exact prior pre-map initialization failure, pinned
sources and coordination locks. It reads the exact A manifest already saved on
B; no active manifest is embedded in this public script. B imports the one
existing 64 MiB object read-only, validates its full hash, then releases its own
maps and emits the production release receipt. Allocation, writes and owner
deletion are forbidden. Existing v2 work/receipts stop duplicate execution.
This step creates no Guest and does not claim two-node DAX or net memory gain.
The A publisher must remain alive. Prior core/main branches remain unchanged.

B script SHA256: e3020b30e278087421552daa084ef9788873baeabb9ced8eaaf2aca5cc2b3f2b

The rootfs comparison packet remains a synthetic cold-boot component test with
its project-built Guest statx helper and source. Global UB physical costs and
original snapshot-CoW benefit remain separate acceptance criteria. No private
benchmark, credentials, active object manifests or measured results are
published on this branch.
