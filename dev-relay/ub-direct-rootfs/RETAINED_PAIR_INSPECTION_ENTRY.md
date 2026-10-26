# Inspect the retained experiment before deciding how to continue

This is a read-only summary of existing real-Guest experiment records. It does
not create or resume a Guest, call an API/SDK, inspect UB payload, clear caches,
modify services/kernel/state, or establish cross-node communication. No target
execution or new Guest result is claimed.

Entry: `AB_inspect_retained_pair_v1.py`.
SHA256: `c652460cf1c8099fe30ad128867c4f05a51b52510e6f487b17eb343bcaf77214`.

After human relay becomes available, use the published fixed entry as root on
each declared node. Default mode prints the plan only:

```sh
python3 -I -B AB_inspect_retained_pair_v1.py --node a
python3 -I -B AB_inspect_retained_pair_v1.py --node a --inspect
```

Use `--node b` on B/agent1. These are alternatives for the appropriate node,
not remote execution commands. Do not run this in the offline user's absence
or ask for nighttime relay.

The entry takes a shared nonblocking lock on the existing pair `run.lock`.
It reads only fixed files under:
`/home/jwk/agent/deployments/agentenv-direct-ub-guest-v1/acceptance/direct-pair-v1`.
It does not create a missing directory or lock. An active controller, missing
lock, invalid owner/type, malformed JSON, redirected path, or a receipt changing
while it is read stops inspection. Both existence and bytes/stat are checked
twice. Existing records and resources are left alone.

Output includes file presence/hash, selected historical run/Sandbox IDs, phase,
pending/error presence, list counts, and command return/timeout fields. It
excludes opaque API responses, credentials, command bodies, raw stdout/stderr,
environment values and free-form error messages. The summary is printed only;
the entry writes no report or target state. Save the returned text privately
if a durable copy is needed.

`RETAINED_PAIR_RECORDS_INSPECTED_NOT_ACCEPTED` means only that these saved files
were inspected. It does not authorize continuation, verify the complete chain,
confirm current PID/binary/liveness, or establish release. Missing files and
empty inventory lists remain unknown. Even a complete-looking local file set
does not set `pairAccepted` or `releaseConfirmed` to true. A recorded identity
conflict is listed explicitly and must be resolved before dependent work.

Use the summary to avoid repeating already completed or uncertain phases.
The original ready request asked for a 7200-second Sandbox lifetime, so an
overnight wait may invalidate assumptions about live Guests. Do not rerun ready,
extend timeouts, retry pending writes, delete journals, or infer cleanup from
missing resources. Current liveness/identity and unresolved requests still need
the existing lifecycle controls and, when necessary, explicit reconciliation.

Once the full pair really completes, use the existing
`AB_pair_evidence_package_v1.py` and complete verifier. This abbreviated summary
is deliberately not accepted in place of the full pair bundle, allocation
ledger or comparison receipts.

Local validation: six record-reader contracts, including real local temporary
JSON reads with unchanged metadata/content, and the default plan. Linux flock,
target root ownership, real Runtime/Guest state and actual hardware were not
exercised. The first local fixture attempt hit Windows mode-0700 sandbox ACLs;
the test fixture directory now uses ordinary inherited directory permissions.
Production target ownership/locking checks were not relaxed.
