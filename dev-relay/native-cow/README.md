# Native CoW experimental relay

Latest consolidated A entry: A_prepare_release_v3.py --run.

This combines finishing the already resized own rootfs copy, building the
coordinated Runtime/CLI/daemon, native verifier and snapshot-aware Firecracker,
and running native protocol tests. No repeated 64 GiB copy/hash or resize.
All source is embedded from core ccd03169cc217590d25c6daa04e576d175d67772;
AGENTS.md symlink is omitted from the no-links source archive. Existing frozen
dependency caches and build target caches are reused. No packages downloaded.
The verifier lock uses only versions/checksums in the Runtime lock.

Deployments and active services are not overwritten. Artifacts and their SHA256
pins are staged under a new build directory. Image finish failure does not stop
independent compilation; the combined report contains both outcomes. No SDK,
Guest, ublk allocation, mount, service restart or hardware acceptance claim.

Important remaining work: native snapshot/Fork hardware acceptance, actual
service activation with retained UB bases, Guest workload comparison and native
memfile private CoW (unimplemented for the tested NC FD). This entry does not
label a build or service health as final cross-node CoW success. Version-3
content references require externally retained immutable base bytes/publications.

SHA256: 2b6a54fce3c7b2cfa1f30b5f2adbe56c25a644882fe934363cf38c59be181df7
