# Explicit cleanup of this field cohort

Normal rollout retains the new Runtime services, the captured templates and the
UB base so results can be inspected. Cleanup is optional and discards the owned
capture. The commands below do not delete other templates, remove repository
directories, free unknown devices, stop UB daemons, or change original services.

First keep the new services active: the API is needed to verify empty inventory
and release captures. On each node, as the ordinary experiment user, run:

```sh
cd /home/jwk/agent
python3 -I -B native_cohort.py --node node-a --variant native --cleanup --release-captures --run
```

Use `--node node-b` on B. Expected completion is
`COHORT_OWNED_CAPTURES_RELEASED_NO_NEW_GUESTS`. The original `report.json` remains
unchanged, and `recovery-*.json` records exactly which UUID/hash was released.
Unknown POSTs, a changed committed record, missing original evidence, a new
Runtime PID/boot/configuration, nonempty inventory or uncertain deletion stops
the operation. Do not erase a journal to bypass those conditions. Re-running
this explicit cleanup performs absence checks, not a second unknown DELETE.

The same mode can release this experiment's **original-variant** capture with
`--variant original`, provided that original service is empty and its existing
replay lock is available. It does not delete the other session's templates.
That original capture does not retain the new UB base, so it can be kept for
later inspection without blocking the new provider's retirement.

After native capture release succeeds on both nodes, release B's import first:

```sh
python3 -I -B native_provider_v4.py retire --node node-b --run
```

Its receipt is `/home/jwk/agent/r/up-b-v4/provider/release.json`. Transfer this
new-generation receipt over the authenticated channel to a new private file on
A, then retire A with that exact file:

```sh
python3 -I -B native_provider_v4.py retire --node node-a --peer-receipt PATH_TO_NEW_B_RELEASE_JSON --run
```

The publisher requires B's matching owner/manifest/reader identity; old-generation
receipts do not qualify. Both providers also check actual active inherited
leases. The wrapper requires all remaining records in this isolated native
repository to be absent, including records outside the one captured by this
cohort. If another valid snapshot exists, retain the base.

The wrapper persists `retire-intent.json` before one control request. An uncertain
call is not resent while the owner is still serving/retiring/unresolved. If the
owner journal already proves complete exact-generation release, the wrapper can
confirm it without another SDK operation. B's deterministic peer receipt can be
recreated from complete finalized and integrity-checked release evidence if the
process was interrupted while publishing that receipt. An incomplete journal
does not permit this reconstruction. `newRetireRequestSent` distinguishes a
newly sent request, a read-only confirmation, and an uncertain send.

Finally request the scoped **new Runtime** rollback blocks on each node:

```sh
python3 -I -B prepare_native_service_v4.py rollback-plan --node node-a
python3 -I -B prepare_native_service_v4.py rollback-plan --node node-b
```

Run each command on its corresponding ordinary-user node and copy its generated
literal block into that node's root terminal. It stops only the verified new
empty Runtime unit and its owned host proxy, while preserving earlier services,
remaining files and reports. It does not stop or recreate UB system services.

The full source image, build inputs, transferred archives and historical logs
remain on disk. They are not RAM-sharing measurements and are not deleted by
these entries. Complete automatic rollout resumption, distributed snapshot
reference counting and recovery across host reboot remain outside this field
cleanup implementation.
