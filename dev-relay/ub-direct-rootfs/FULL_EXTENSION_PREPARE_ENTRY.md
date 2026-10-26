# Four-template metadata preparation — allocation remains blocked

`AB_prepare_full_extension_v1.py` packages core candidate
`7ea21539874953d42d34fa3dd66a2e154139ece9` and exposes only `--prepare`.
Without that flag it prints a plan. It has no provider start, SDK initialization,
Guest, service, kernel, port or lock-change action.

If later explicitly run on A/server1 or B/agent1, use ordinary jwk, zero
capabilities and the matching `--node a|b`. No command is being requested from
the offline user, and this entry has not been run on either node.

It verifies the node's existing four-template seed SHA256, each catalog SHA256,
resource configuration and ordered committed lower list. It de-duplicates the
lower contents and checks only ordinary-file attributes. It does not read or
copy lower payload or decode private replay commands. The retained provider's
owner/manifest, eight-object index, Runtime index pin, mapping coverage and
PID/startTicks/boot are checked. Uncertain identity stops preparation.

Fresh output directories are `/home/jwk/agent/r/uf4-meta-a-v1` and
`/home/jwk/agent/r/uf4-meta-b-v1`. Existing directories are preserved. Outputs
include the pinned preparation source package, `plan.json`, immutable file
identities, `provider-proposal.json` and `report.json`. These are private field
metadata, not GitHub publication inputs. Preparing them may warm small metadata
and Python source files; perform preparation outside the measurement window.

The expected successful preparation status is
`FULL_EXTENSION_METADATA_REVIEW_REQUIRED_NO_SDK`. It still records
`readyForAllocation=false`, `providerStarted=false`, `SDKCalled=false`,
`GuestCreated=false`, and `runtimeIndexInstalled=false`.

## Newly identified SDK guard restriction

The already running full entry's `provider_inside()` acquires
`/home/jwk/agent/relay/ub-layer-sdk-node-<a|b>.lock` using an exclusive flock and
holds it throughout `service.serve()`. Launching another provider through that
same entry is therefore blocked while the retained provider remains active.
This restriction was identified in local entry source; no target probe was used.

The preparation may read the exact guard inode's rows from `/proc/locks`, but
never acquires, releases, unlinks, replaces or bypasses the lock. Missing rows
are not proof that concurrent SDK startup is allowed. The proposal contains
`serviceConfig=null` and `launchable=false`, regardless of observed rows.

Inspection of the fixed local UBS-MEM source found process-local initialization
state/mutexes and process-specific shared-memory reference records. This is not
proof of installed multi-client behavior. The current blocker is the experiment
entry's exclusivity policy plus unverified native coexistence, not a proven
hardware prohibition. A controlled change to that policy, bounded coexistence
and recovery handling must be reviewed before any second SDK client is started.
No such change or launch has been authorized or performed by this entry.

## Capacity and rollout gates

The current explicit total budget remains 4 GiB. It is not silently raised to
the historical four-template estimate. The planner records retained reported
export coverage once and the additional projected coverage; B's import windows
are not a second allocation. The historical estimate is 46 unique contents,
8 retained plus 38 new, totaling approximately 11.125 GiB under the observed
128 MiB region assumption. Current seed-backed preparation and actual SDK
coverage must be distinguished from that projection.

Preparation does not emit a valid service configuration or start command. The
budget, SDK guard/coexistence restriction and missing real Guest acceptance are
all listed in `blockedBy`. Do not manually unwrap or bypass those conditions to
start the generic provider.

The existing smaller full Guest experiment and original/full comparison can
continue using the retained eight-object providers once their real acceptance
receipts and human relay are available. They do not need a second SDK client.
The sixteen-Guest objective remains pending; this metadata entry does not claim
that four-template publication/import or Runtime staging is complete.
