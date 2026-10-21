# One A terminal, two scoped root activation blocks

`native_rollout.py run-a --run` is the coordinated **field execution candidate**.
It has not been executed on the two hosts. It prepares and runs the implemented
rootfs path; native memfile private CoW is still unimplemented. It will produce
an incomplete comparison when required observations or functional steps fail.
It cannot guarantee positive savings or turn missing measurements into zero.

Download the entry from the fixed experiment commit, verify its supplied SHA256,
and save it as `/home/jwk/agent/native_rollout.py` on A. Start it in the ordinary
experiment user's terminal:

```sh
cd /home/jwk/agent
python3 -I -B native_rollout.py run-a --run
```

Keep that terminal open. It downloads twelve public helpers at an immutable
GitHub commit and verifies their hashes. Existing files with different contents
are preserved and stop the run. It uses the already configured A-to-B SSH trust,
requiring batch authentication and strict host-key checking. It does not create
credentials, change known_hosts, or weaken SSH checks.

The automatic sequence is:

1. Finish the already resized private rootfs copy, add/verify the executable
   DAX marker, and build the coordinated Runtime, CLI, daemon, verifier and FC
   using the existing offline dependencies and compilation caches.
2. Pack the original immutable OCI/commit inputs separately from the binaries
   and tools. Transfer them privately A-to-B, with bounds, SHA checks and fresh
   destinations. Prepare both providers and new service directories, then seed
   both new image caches. No live database is copied.
3. Perform the guarded handoff of this experiment's known old 64MiB generation.
   B holds the SDK fence while the old owner retires its own object. Unknown
   objects and existing UB daemons are not stopped or deleted.
4. Run the original two-Guest cohort on each node before publishing the new UB
   image. Each node holds its two Guests after the workload until both nodes'
   post-workload samples have completed. This is a coordinated hold, not an
   atomic hardware snapshot or synchronized workload instruction start.
   Known owned Guests are cleaned. Any unconfirmed cleanup stops progression.
5. Print **one A root block** containing the new provider and new Runtime unit
   activation. Copy that block into A's root terminal. The ordinary A terminal
   waits for provider/service readiness for up to 15 minutes.
   A known terminal provider journal or failed/exited Runtime stops immediately;
   it is not mislabeled as another 15 minutes of waiting for your root action.
6. Transfer the newly published owner manifest to B and validate it against B's
   prepared content. Print **one B root block**. Copy it into B's root terminal.
   The same ordinary A terminal waits and then checks both new Runtime services.
7. Run the native cohort on both nodes, gather the four reports, and generate
   the comparison on A. This uses real cold/capture/restore/Fork/exec/delete API
   requests, not merely health endpoints.

The two root blocks run their literal, hash-checked scoped activation code. They
do not run the coordinator as root. Existing Runtime configurations/binaries,
unknown sandbox state, system permissions and driver limits are preserved.
No machine-wide cache flush occurs. Preparatory hashing/copying warms file
cache, so the run makes no cold-cache claim.

## Output and interruption

All orchestration output is retained under `/home/jwk/agent/r/cow-rollout-v4`:

- `steps-node-a.json` / `steps-node-b.json`: stage state, exit codes and log paths.
- `logs/`: complete build/prepare/control/cohort phase output.
- `hold-VARIANT-EPOCH/` and `pair-VARIANT-EPOCH.json`: immutable readiness,
  measurement and cleanup-release evidence; RPC diagnostics remain in `logs/`.
- `root-node-a.txt` / `root-node-b.txt`: the generated literal activation blocks.
- `original-node-a.json`, `original-node-b.json`, `native-node-a.json`,
  `native-node-b.json`: the returned cohort reports, also retained in each
  cohort's own report directory.
- `comparison/comparison.json` and `comparison/comparison.md`: final local
  descriptive comparison with missing metrics explicitly marked NA.

The completed coordinator status means its sequence and report generation
finished. Read the comparison's `allFourFunctionalCohortsPassed` and missing
evidence fields. It does not mean memfile CoW or global net savings passed.

If a phase stops, keep all directories/journals and inspect that phase's log.
Do not rerun `run-a` from the beginning, delete a pending file, recreate a
publication, or free devices to bypass the failure. The entry refuses an
existing rollout journal. Complete automatic rollout resumption is not yet
implemented; exact phase recovery must use its retained receipts. A timed-out
SSH/API operation may still be active remotely.

An interrupted cohort can use the same pinned `native_cohort.py` with
`--node NODE --variant original|native --cleanup --run`. This requires the same
recorded boot/Runtime/configuration and coordinates through the same locks. It
does not create another batch. It can reconcile a stored successful response or
confirm deletion via GET 404, but it leaves unacknowledged POSTs pending. Its
separate recovery report preserves the original measurements; see COHORT.md.

For an interrupted old-generation handoff, the already supplied
`legacy_provider_handoff.py resume-a --run` reconciles its recorded nonce and
receipts without resending an uncertain deletion. For a new Runtime that is
quiescent, `prepare_native_service_v4.py rollback-plan --node NODE` prints the
scoped rollback block described in DEPLOYMENT.md. It preserves snapshots and
the UB provider. Provider retirement is separate and refuses retained snapshot
records; this cohort intentionally retains captures. Do not terminate a live
provider to reclaim its base while those references remain.

## Remaining gaps

The coordinator does not add a KVM-compatible UB private-write fault mechanism.
It does not attach a privileged RAM sampler or the Host lower-read observer, and
the coordinated post-workload hold is not an atomic physical snapshot. Ordinary
`proc` permissions can leave RAM metrics unavailable. Host actual-access versus
residency intersections, UB physical charge and complete helper/cache ownership
remain missing. Sub-cgroup differences must not be presented as global net
savings. See COHORT.md for exact measurement scope and formulas.

Actual bound private-upper cache and the new provider's process/cgroup overhead
are now sampled when available. Provider SDK-journal coverage is shown only as
mapping evidence. Neither it nor provider RSS substitutes for total UB physical
cost, and upper/Guest-cache values are not added to totals that already include
them.

Local checks exercise ordering, fail-stop behavior, integrity/refusal rules and
the generated command structure. They do not execute SSH, Linux systemd, the
SDK, KVM, or the actual Guest workload. The first field run remains acceptance
testing, with full logs and preserved failure evidence.
