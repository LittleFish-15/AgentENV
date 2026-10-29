# Demand runtime entry (development, native acceptance pending)

The production aenv/OverlayBD read backend is selected by
`AENV_ROOTFS_BACKING_MODE=ub_demand` and `AENV_UB_ROOTFS_DEMAND_INDEX`.
The old full index must not be present in that process's environment. Derived
lower configs contain `demand` references and no ordinary-file fallback.
Memory backing and the independent full-mode services are not replaced.

The provider package now has one executable assembly module,
`aenv_ub_provider.demand_runtime`, rather than requiring callers to instantiate
unconnected classes. The `components/ub-memory-provider/start.sh` entry exposes:

| Action | Effect |
|---|---|
| `check` (default) | Local test suite; optional private config validation. No SDK |
| `prepare` | Explicit O_DIRECT manifest preparation of retained layers; no UB |
| `build` | Ordinary-user Linux build of server and ublk daemon; prints hashes, no deployment |
| `validate` | Validate trusted manifests and explicit role binding; no source scan or SDK |
| `serve` | Run exactly the configured owner, node, or root role, in the foreground |
| `status` | Query the role's existing local/control service |
| `drain` | Node only: refuse live aenv sessions, then retire local views/imports |
| `close-admission` | Owner only: refuse new acquisitions, preserve existing reads |
| `finish` | Owner only: delete unpinned objects only after authenticated node receipts |

Set `AENV_DEMAND_CONFIG` to an absolute, owned 0600 JSON file. Serving requires
the explicit run-scoped `AENV_DEMAND_APPROVAL=UB_DEMAND_<32-hex-run>` marker.
That marker is an operator guard, not a substitute for approval of the actual
resources/budget. Root/SDK role privileges are checked independently. Do not
serve with guessed profiles, use another experiment's approval, or load modules
through this entry.

Common configuration fields: `version:1`, `role`, `run`, `node`, two-element
`nodes`, `ownerNode`, isolated absolute `stateRoot`, and `manifests`. Each
manifest row has its trusted canonical document and `sha256`; the owner also
has `sourcePath`. Startup validates metadata, not all payload bytes. Source
chunk hashes are checked when a miss actually builds a new immutable image.

Owner fields: `adapter`, `adapterSha256`, `region`, `mke2fs`, `budgetBytes`,
`imageKey`, per-node `receiptKeys`, `listenHost`, `listenPort`, TLS files and
`nodeFingerprints` (certificate SHA256 -> node). Control TLS client settings
also need `url` and `serverFingerprint` for owner administrative commands.
The SDK owner state/socket root is `<stateRoot>/publisher`.

Node fields: `rootSocket`, `adminSocket`, `indexPath`, `layers`, `tls`,
`budgetBytes`; non-owner nodes also need adapter identity and region. TLS has
`url`, `ca`, `certificate`, `key`, `serverFingerprint`. Each layer uses the
Rust `DemandLayerRef` camelCase schema. SDK import sockets live in
`<stateRoot>/sdk`; local chunk broker sockets in `<stateRoot>/chunks`.

Root fields: `imageKey`, node `receiptKey`, `rootSocket`, `rootConfig`.
`rootConfig` binds `uid`, `gid`, `agentUnit`, `sdkUnit`, `sdkRoot`,
`brokerRoot`, `moduleSrcversion`, `kernelRelease`, `imageBytes:134217728`,
`maxViews`, and optional `payloadResponses`. `agentUnit` is the node process;
on the owner node `sdkUnit` is the owner process. On the importing node it is
the node process. They must match actual system units and peer credentials.
All socket paths must meet the underlying short Unix path constraints.

Use one fresh private state directory per role/run. Existing state is rejected
without repeating SDK operations. The current implementation does not provide
crash recovery from an old root/session process. Preserve logs and objects and
perform explicit reconciliation; do not delete state to bypass that gate.

Start root supervisor and owner, then node agents, then the isolated aenv
runtime using the generated metadata index. Exact system unit/config generation,
pinned deployment packaging and Linux native service integration are still
required before this can be described as a ready two-node launch.

Normal retirement: stop only this run's Guests/runtime/ublk consumers; close
owner admission; drain both node agents; finish owner global release after both
receipts. Stop the empty processes afterwards. An unknown result preserves
resources. This entry never restores or unloads OBMM or stops UBSE.

The default-full-feature ARM64 OverlayBD library and all test targets now
compile with the isolated, official-hash-verified Rust 1.91.1 compiler. The
actual production AppConfig source also compiles in a focused harness and its
new startup validation test executes successfully; unrelated volume/P2P identity
constants in that harness are fixtures. This is not a complete aenv build.
That main-library cross-check still needs ARM64 OpenSSL development libraries.
No native/two-node demand acceptance or savings are claimed here.
