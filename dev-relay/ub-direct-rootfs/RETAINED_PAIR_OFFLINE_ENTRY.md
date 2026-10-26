# Offline first step after human relay resumes

Use `AB_inspect_retained_pair_OFFLINE_root.sh` as an alternative to downloading
the already fixed Python inspector. It contains exactly that entry in a bounded,
SHA256-checked compressed payload and runs it in memory. It does not install a
file, download anything, invoke an API/SDK, create a Guest, change services or
kernel, release resources, clear caches or establish a cross-node channel.

Wrapper: 5359 bytes, SHA256
`ee52e919a2a8ca4cc3a48490adb016e70b8c1c87fb71e124013711d18c8c558e`.
Embedded Python: 7769 bytes, SHA256
`c652460cf1c8099fe30ad128867c4f05a51b52510e6f487b17eb343bcaf77214`.

After the user returns, the same complete shell block can be pasted into a
root shell on A/server1 and B/agent1, once per node. It requires the exact node
name, root real/effective UID, Linux and Python 3.11 or newer. It chooses only
the matching local node; there is no remote invocation. An unknown node or
identity stops before inspection. Do not execute or request relay overnight.

`RETAINED_PAIR_OFFLINE_ENTRY_VERIFIED` confirms only the embedded script bytes.
The expected subsequent block is `BEGIN_RETAINED_PAIR_INSPECTION` through
`END_RETAINED_PAIR_INSPECTION`. Its status is explicitly not acceptance. It
summarizes existing fixed pair journals under a shared nonblocking lock;
missing/busy/changed/invalid records stop or remain unknown. It never retries
pending phases, creates missing journals, or infers release from empty lists.
Raw Guest output, private workload and credentials are excluded.

This reduces the first state handoff to two local invocations and their returned
summaries. It does not eliminate subsequent real cross-node receipt dependencies
or prove that the old Guests are still alive. The earlier requested 7200-second
Sandbox lifetime may have elapsed. Do not rerun ready or discard pending state
to replace missing/expired evidence.

If all local phases are actually complete, the existing complete evidence
collector and pair verifier remain mandatory. This summary cannot replace
their bundle or the comparison allocation ledger. Existing full-mode code,
provider objects, binaries, configuration and deployment remain unchanged.

Local validation covers exact embedded bytes, bounded decoding, Python 3.11
syntax, shell delimiter structure and wrapper guard/dispatch logic with local
identity doubles. No Linux shell/lock, target records, SDK or Guest was run.
See `RETAINED_PAIR_INSPECTION_ENTRY.md` for the inspector's separate checks and
interpretation limits.
