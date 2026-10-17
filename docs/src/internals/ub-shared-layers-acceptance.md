# UB layer reuse: acceptance status

2026-10-17. **Experimental implementation; target acceptance is incomplete.**
Scope is the explicitly selected UB snapshot-layer reuse plus each node's
original local CoW, including immutable rootfs lowers. The source baseline is
`ae9c62693839ce7effa2b45df31c0039ae4f9fbc` / 0.2.2. Nothing below claims physical
Guest RAM Base sharing, zero-copy, measured memory savings or automatic cluster
placement. The [review](ub-shared-layers-review.md) distinguishes baseline source
facts, the prior ordinary-object UB experiment, assumptions and required tests.

## Results by requirement

| ID | Required behavior | Implementation / local evidence | Target result |
|---|---|---|---|
| A1 | A/B memory lowers use one object/generation; B allocates zero; actual broker reads | Stored-identity binding, importer and generation-bound client implemented. Real Rust/Python wire interoperation passed. | New bridge/broker and memory ublk/Guest path not run on A/B. |
| A2 | Rootfs immutable lowers shared through UB; independent writable uppers | Both fresh/resume rootfs construction and snapshot resolvers bind UB views; original upper construction remains. | Actual rootfs layer/upper probe and Guest disks not run. |
| A3 | Raw, tar, ZFile/LSMT bytes parse correctly; EOF/ranges are correct | Original adapters retained. Wire EOF/range/chunk/error tests passed. The real-format/private-upper/durable-child probe cross-checks for ARM64 Linux. | Raw/tar/ZFile runs prepared, not executed. Cross-check is not runtime proof. |
| A4 | Guest RAM restored; first and repeated writes stay private; base/sibling unchanged | Original Firecracker File RAM restore unchanged; no direct UB RAM mapping introduced. | Both original Guest baseline and modified A/B Guest tests remain mandatory. |
| A5 | Capture-consistent dependencies and durable multi-generation closure; unchanged ancestor reuse | Original capture retained. UB ancestors are stable lowers; POSIX/OSS publication exports and verifies stored bytes. Publisher tests demonstrate borrowed ancestors allocate/delete zero and need no local duplicate. | Full server integration, real recapture and durable repository reopen not run. |
| A6 | No release while active; correct owner cleanup; unknown state preserved | Live/in-flight lease rejection, SDK-busy, failed-unmap, unknown-create, owner/borrower and history tests passed. Receipt writes and parent directories synced. | New bridge unmap/delete/finalize and interruption recovery need SDK execution. No independent global absence query claimed. |
| A7 | Broker loss/short replies do not produce partial success or corrupt siblings | Protocol fault tests passed. Full-range verified fallback and shared-session/export tests type-check for Linux. Fallback is explicit local-file only. | Linux fallback tests and process-fault/Guest behavior not executed. |
| A8 | Disabled feature and legacy configs retain baseline; actual source/degradation visible | Optional field omitted when absent; opt-in environment hooks return original paths when unset. 39 actual config/protocol tests passed on Windows with one existing POSIX-path-only case filtered. | Linux legacy config run and actual opt-out runtime regression pending. |
| A9 | Only AgentENV modified; no external component/system/privilege changes | Source changes confined to AgentENV. Public SDK headers read for compile only; no remote connections, service/device/ACL/capability changes performed by this implementation work. | Target scripts enforce original ordinary jwk/workspace; future operations must preserve scope. |
| A10 | Reviewable commits, checks, fork delivery and complete relay commands | Review, broker/protocol, runtime integration and offline/one-pass acceptance are separate commits on `LittleFish-15/AgentENV:feat/ub-shared-snapshot-layers`. Remote Git objects matched local SHAs; main unchanged. | Source and smoke delivery prepared; reports from target commands remain required. |

## Local checks actually performed

- 39 tests of the **actual** config/protocol source, plus 24 actual Python
  publisher/broker tests (including the compiled actual Rust wire client), plus
  6 smoke transfer/receipt guards: **69 distinct tests executed successfully**.
  The standalone 8 protocol tests were also rerun; they overlap those 39.
- One unchanged baseline test expects POSIX `/tmp/...` path spelling. Its Windows
  path-separator failure was recorded and it was filtered in the successful
  Windows run; it is not counted as passed. The offline Linux build script runs
  all config tests, including this case.
- The full real OverlayBD library with io-uring and its dependencies cross-checks
  for `aarch64-unknown-linux-gnu`. The harness directly imports the real UB
  backend/config/VirtualFile files; those files, four Linux-only backend tests
  and the real layer probe pass clippy with `-D warnings`. Dependency checking
  is not claimed to lint every pre-existing OverlayBD module.
- The C++ bridge compiles into an ARM64 ELF object against the supplied public
  SDK header with `-Wall -Wextra -Werror`. This is neither SDK linking against
  the installed nodes nor a hardware mapping test.
- Changed Rust files pass rustfmt; Python sources parse; Git diff whitespace
  checks pass. Cargo.lock and dependency manifests are unchanged.

The full AgentENV server/daemon workspace has **not** been compiled in the local
Windows environment. Linux native dependencies and target execution are still
required. The source-derived ARM64 checks above do not cover every `src/`
integration module. This limit must not be reported as a full build pass.

## Target sequence and unresolved assumptions

Follow [the complete tool instructions](../../../tools/ub-snapshot/README.md):
E2 uses one 4MiB NC object through this bridge/broker, then A performs a frozen
offline full build, then one-pass E3 separately tests raw/tar/ZFile layers on
both nodes. Each format uses one small object, two private uppers and durable
child reopening; owner cleanup follows complete peer exit. No service or VM is
started by E2/E3/build scripts. All reports are printed automatically.

Formal Guest acceptance follows the original Runtime baseline and a separately
isolated modified deployment. It requires a validated offline template,
experimental endpoints and a complete durable snapshot transfer/catalog path.
A Ready UB index alone cannot restore VM state or missing disk dependencies.
Plan real stored/mapping byte totals before increasing the small test budget;
there is no known service-enforced quota. Missing target inputs/permissions are
reported, not bypassed by installing components or escalating privileges.

Still assumed: compatible installed SDK/provider/daemon semantics; no external
writer changes Ready objects; immutable durable fallback files; compatible
Guest snapshot ABI; operator-confirmed consumer shutdown before retirement.
SDK busy/unknown creation leaves receipts unresolved. No timeout alone deletes
objects. Local caches and broker copies remain. No performance or physical-page
uniqueness conclusion follows from these correctness checks.
