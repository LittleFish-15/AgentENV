# Offline full/original comparison verification

`aggregate_full_pair_comparison_v1.py` is an offline receipt verifier and
endpoint-sample summarizer for the fixed first-template comparison controller
SHA256 `1fdd764fd0337a5362a16f402f181261d8eccb0ba0d96b728d230d44fcf9c38d`.
It embeds four previously published, SHA-checked contract/accounting modules.
Its exact bytes/hash are in `full-pair-comparison-packet.json`.

It does not connect to a node, run a Guest, execute a workload, change services,
call an SDK, allocate/release objects or manipulate caches. No real comparison
inputs have been received or processed at publication time.

## Inputs

After actual experiment completion and authorized human transfer, each local
node directory must contain `original/` and `full/`, each with:

- `receipt.json`, `replay.json`, `bindings.json`;
- `before-guest-create.json`, `baseline.json`, `final-before-release.json`.

These are existing outputs of the fixed local comparison executor; do not
recreate them from summaries or rewrite incomplete states as successful.
The accepted real Guest `pair-bundle.json` and retained
`allocation-ledger.json` from the evidence merger are also required.
Files remain private experiment evidence. Do not publish them to GitHub.

Local invocation (no target operation):

```text
python aggregate_full_pair_comparison_v1.py --a <local-A-results> --b <local-B-results> --pair-bundle <pair-bundle.json> --allocation-ledger <allocation-ledger.json> --output <new-comparison.json>
```

Existing output is not overwritten. Missing/partial/invalid inputs fail before
writing the result. The component verifies the original complete two-node
Guest receipt chain, exact original/full binaries, declared template/lower and
replay signatures, every command result, actual FC/daemon bindings, UB read
events, acknowledged creation/release sets and provider drain. Changed
timeouts, fallback, unknown POSTs, unconfirmed device exit, reused Guest IDs,
duplicate process/inode accounting and different export epochs are rejected.

The current pin accepts only the first template, two Guests per node per
variant: **four Guests across nodes per variant**. It cannot certify the
four-template sixteen-Guest target, which still requires extended content,
capacity approval, SDK coexistence/deployment and its own validated execution.

## Output meaning

Known nonzero command exits are counted and compared. A mismatch is preserved
as `COMPLETED_RECEIPTS_WITH_COMMAND_OUTCOME_DIFFERENCES`, with per-command
differences; it is not silently accepted as matching behavior. Complete matching
receipts use `COMPLETED_FIRST_TEMPLATE_COMPARISON_RECEIPTS_VERIFIED`.

For each node and variant, output includes:

- completed Guest/command counts and nonzero counts, restore and replay elapsed
  time; elapsed percentage changes remain descriptive, not controlled causality;
- distinct pre-creation, pre-replay and final snapshots, with both cache-growth
  reference points clearly named;
- ordinary-file residency by category, whole-process PSS by role and process
  counts, raw separate device and Guest RAM observations;
- original-minus-full Host lower cache-growth difference per node, including
  negative values; unavailable file categories remain null, never zero;
- one retained unique export reservation ledger for both variants. Importer
  mappings are not charged as a second pool. The pool's original-phase
  background occupancy is explicitly retained in the output.

The pre-creation process scope includes both Runtime variants, while replay
sampling includes the active variant; these PSS scopes are not subtracted as
if identical. Original/full upper policies are preserved and reported.

The sum of separate node cache-growth differences is **not simultaneous
cluster residency, a PFN union, or net savings**. Wall clocks, overlapping
windows, access/residency intersections, incremental physical UB charge and a
disjoint total are not established. FC PSS, Guest RAM, device cache and Host
Cached overlap and are not added. Index/decompression/response subdivisions
and transient CLI PSS are not independently measured. Net savings stays null.
Raw `samples.jsonl` is not replayed by this endpoint summarizer, so peak or
full time-series completeness is not claimed.

Eight in-memory synthetic contract tests exercise missing measurements,
negative differences, mismatched outcomes, fixed identities, failure retention,
scope limits and no double-counting. Synthetic fixtures are never saved as
field reports. Passing these tests does not constitute real aenv acceptance.
