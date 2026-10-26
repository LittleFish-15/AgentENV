# Extending a full UB rootfs set without copying retained objects

The `aenv_ub_provider.full_set` module plans missing stored-layer contents and
composes ready indexes from independent `stored-direct` providers. It performs
no SDK operation and reads only metadata and file attributes. It does not
deploy a Runtime, mutate an existing index, transfer files or authorize memory
allocation. Existing full and pmem deployments remain independent.

## Runtime path and ownership

The Runtime already supports a distinct `brokerSocket` in every `UbLayerRef`.
`RuntimeReadLeases::acquire` opens/holds each required reference, and the daemon
opens its own sessions through `UbLayerFile`. The registry key includes socket,
object name, generation, content digest and lengths. Thus a derived rootfs can
retain old layers through the old broker and read newly published layers through
another broker. Required mode still rejects repository fallback.

The added provider owns only missing contents. It neither imports nor republishes
the retained objects and does not borrow a parent's SDK mappings. The two old
providers stay alive. Each existing owner keeps its own configured importer
registration and release-receipt rules; a merged index is not a new owner and
does not replace either provider's lifecycle journal. In particular:

1. Compose metadata only after both publication groups have ready manifests and
   exact node-local indexes. A and B have different broker socket paths but must
   describe the same content/object/generation identities.
2. Runtime permits and daemon sessions directly hold both brokers while Guests
   use their lowers. Removing one Guest must leave the other Guest's sessions.
3. After Guests/ublk/read sessions drain, keep both provider groups for any
   remaining comparison. Do not interpret a metadata index as a lease.
4. Final retirement is independent: each importer must finish unmap/finalize and
   produce that owner's exact release receipt before its owner can retire.
   A receipt for the new group cannot release the old group, or vice versa.
   Unknown outcomes remain under their existing journals.

No new parent-lease protocol or cross-node communication service is introduced.
Native simultaneous SDK use by multiple providers, multi-broker actual Guest
reads and final hardware release remain target acceptance gates.

## Planning and composition

`python -m aenv_ub_provider.full_set plan --help` exposes the metadata planner.
It takes ordinary image configurations, sourceRoot, a pinned retained fragment,
reported retained coverage, an explicit coverage-quantum assumption and total
coverage budget. The retained fragment descriptor has four fields:
`manifest`, `manifestSha256`, `index`, `indexSha256`. The manifest pin uses the
provider's canonical manifest identity; the index pin hashes exact file bytes,
matching the Runtime's index configuration. This descriptor is local metadata,
not an SDK initialization request.

Planning writes a fresh `plan.json`. If the projected total exceeds the declared
budget, it reports the shortfall and emits no publication input. If it fits,
`new-layer-publication-input.json` contains only missing contents. This is a
publication-only list for the existing `stored-direct` service's `images`
configuration; it is not a filesystem or Guest image. SourceSet later performs
its existing complete direct-I/O validation before any SDK allocation.

Use `newMappingBytes` for that new generation's explicit logical budget and
`newCoverageBudgetBytes` for its post-map coverage guard. An estimate is not a
physical hard quota: SDK allocation can precede discovering actual coverage.
Actual exported regions must be checked/deduplicated before deployment or any
benefit claim, with uncertainty and retained old costs accounted separately.

`python -m aenv_ub_provider.full_set compose --help` accepts the pinned plan and
ready fragment descriptors. It refuses missing/extra/duplicate contents,
changed retained objects or generations, duplicate owners, broker aliases,
unregistered importers and any fallback-enabled reference. It writes a fresh
runtime index plus a composition record with the index's exact SHA256, each
owner's manifest identity and a node-independent content-set identity. All
output remains metadata-only (`liveLeasesAttested=false`).

The composition record does not claim active process identity, current physical
mapping, provider health, actual SDK budget conformance, Guest reads or savings.
The deployment/acceptance controller must check those on target. It must also
prepare all selected snapshot records/binds and pin this new index in a separate
or explicitly reviewed Runtime configuration. Never overwrite the retained
first-template provider index or silently change a healthy service.

## Tests and validation boundary

Python tests exercise missing-only planning, budget refusal, multi-owner exact
coverage, stable imported identities despite local socket differences, rejection
of stale/replaced references and independent retirement membership. Rust tests
exercise actual RuntimeReadLeases and UbLayerFile wire sessions against two local
Unix brokers, plus release of partial permits when the second broker is absent.
These are protocol/lifetime tests, not SDK or two-node physical-sharing proof.
Native execution and end-to-end Guest validation must be reported separately.
