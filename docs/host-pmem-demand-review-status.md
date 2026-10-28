# Host DAX demand integration: development review snapshot

Status: **WIP / NOT DEPLOYABLE / NOT TWO-NODE ACCEPTED**.

This snapshot exposes the actual in-progress aenv integration for review. It is
not a release artifact, deployment instruction, or claim of hardware savings.
The independent full-mode branch and running target services are untouched.

## Review scope

- `src/cfg.rs`: explicit rootfs backing mode and demand metadata index.
- `src/snapshot/runtime_support.rs` and the POSIX repository runtime: choose the
  demand schema explicitly, preserving the legacy memory path.
- `storage/overlaybd/src/config.rs`: typed demand references, identity checks,
  metadata-only binding, and removal of ordinary source/download fallbacks.
- `storage/overlaybd/src/backend/demand*.rs` and `image/image_file.rs`: actual
  `VirtualFile` / `read_at` backend and lower-layer selection. Opening a demand
  session exchanges metadata; reads carry a request ID and byte range.
- `demand_control.py`: authenticated control transport, operation IDs, shared
  publication grants, and retirement receipts.
- `demand_importer.py`: SDK import/map/unmap ownership; importing nodes do not
  allocate their own content objects.
- `demand_views.py`, `region_provenance.py`: root DAX view supervisor, local
  broker client, and bounded OBMM source-identity evidence collection.
- `demand_service.py`, `demand_wire.py`: node-local view registry and logical
  reads routed to the required immutable chunks.
- `demand_native.py`: SDK finalization acknowledgment guards.

The branch also incorporates the previously reviewed full-mode inherited-FD
rootfs bridge as a dependency. Those files are reusable infrastructure, not
evidence that the demand chain has been accepted.

## Verification at this snapshot

- Provider suite on Windows: 200 tests, 199 passed, one native Linux O_DIRECT
  test skipped. Existing tests do **not** cover the complete new service chain.
- Six new Python service modules import successfully; this is a syntax/import
  check, not execution of their Linux/SDK/root operations.
- Standalone Rust protocol harness: 12 passed.
- Harness compiling the actual OverlayBD config and protocol sources: 42 passed,
  five existing POSIX path tests excluded on Windows. This count includes the
  protocol tests; the two counts must not be added as unique coverage.
- `git diff --check` passed; publication excludes credentials, private payloads,
  and field reports.
- The complete aarch64 OverlayBD cross-check has **not passed**: the local C
  dependency compiler encountered `AccessDenied`. Full aenv build, workspace
  formatting/clippy, and Linux integration checks remain required.
- No target SDK operation, module change, service deployment, Guest launch,
  two-node demand acceptance, or demand-savings measurement was performed.

## Work still required before deployment

1. Assemble owner/node/root roles into executable, validated configuration and
   service entry points. The current classes alone are not an operator entry.
2. Test the actual Rust-to-service path, concurrent first misses, repeated reads,
   cross-chunk reads, authentication, lost responses, and error propagation.
3. Complete retirement and explicit reconciliation tests, including partial
   failure and uncertainty. Never repeat an unknown SDK allocation/deletion.
4. Finish build, formatting, lint, and regression checks on the integrated code.
5. Produce pinned binaries, manifests, and a reviewed two-node deployment and
   recovery entry. Only then request the necessary field operations.
6. Run the minimal real Guest overlap/repeat/untouched-range test before larger
   experiments. Report cache avoided separately from unique UB capacity and
   measured physical increments; unknown overall savings stay NA.

The current reviewed SDK/configuration uses 128 MiB allocation/import alignment,
and sealing is per region. Demand loading does not promise that the small
64 MiB example will use less than 128 MiB. See `host-pmem-demand.md` for the
design, limits, and acceptance gates.
