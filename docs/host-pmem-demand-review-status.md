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
- Update: the actual aarch64 OverlayBD library cross-check now passes after
  resolving the local compiler-cache permission issue. This compiles the new
  production VirtualFile backend, not just a protocol harness.
- An isolated Rust 1.91.1 compiler and host/ARM64 standard libraries have now
  been obtained and verified against official SHA256 records. With that
  compiler, the default-full-feature ARM64 OverlayBD library and all test
  targets compile, including the actual VirtualFile/Unix test. The tests have
  not executed on Linux. Main aenv checking now reaches the cross OpenSSL
  development-library requirement; it has not yet passed. Formatting/clippy
  and native integration are still pending.
- Actual owner/node/root role assembly and a foreground debug entry now exist
  in `demand_runtime.py` and `start.sh`. Seven role/startup tests, one overlap and
  retirement service-chain test and three broker-wire tests pass. SDK/DAX and,
  in the service-chain test, journal storage are mocked boundaries.
- An actual production Rust Session interoperates with the actual Python
  broker over a loopback TCP test transport (open, read, EOF clamping and lease
  exit). Payload mapping is a test double. This is not the complete native
  VirtualFile/Unix/SDK/Guest path.
- Node-agent diagnostics now record bounded request timing/bytes without
  payloads, report dropped tracing explicitly, and return a bounded admin
  summary instead of full publications/receipts. No per-read fsync is added.
- `start.sh prepare` explicitly prepares trusted manifests from retained
  layers through O_DIRECT, separate from runtime startup and UB allocation.
- No target SDK operation, module change, service deployment, Guest launch,
  two-node demand acceptance, or demand-savings measurement was performed.

## Work still required before deployment

1. Finish concrete two-node role configuration, trust provisioning and system
   unit packaging around the executable role assembly. The current debug entry
   alone is not a ready target deployment.
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
