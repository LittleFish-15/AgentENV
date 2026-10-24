# Parent-preread x block/DAX controlled snapshot experiment

This is a new single-node component controller, not the old cold-boot/no-api
8 MiB experiment with renamed groups. No existing Runtime or provider is used
or replaced. No UB SDK, kernel/driver changes, reboot, network or global cache
eviction occurs. A new bounded transient comparison unit is started only by
the human's printed root command. Fixed order: B0, D0, B1, D1; one trial each.

## Inputs and preparation

Reuse the completed Host-file component's pinned kernel, tools image, initial
upper and exact 64 MiB lower containing the same 8 MiB common-data.bin. Reuse
the successfully built snapshot-aware FC with SHA
4954397edf0b849b87ef114d86897f41f475b2a98a0338bcb6c4abdef74197e7.
All groups use that same FC and the same newly prepared tools copy. The original
tools image is preserved. A static ARM64 Guest helper and init script are inserted
only into the new copy using the existing debugfs, then round-trip verified.
No target package installation or binary download beyond the fixed entry.

Ordinary jwk on A executes the entry's `prepare`. The entry refuses an existing
stage rather than overwriting it. Target namespace: /home/jwk/agent/r/pcc-parent-v1.
Preparation records Host/process/file observations before hashing/copying and
after completion. Run admission also records before/after verification costs.

The printed PCC_REVIEWED_ROOT block creates jwk-pcc-node-a-v1.service with
User/Group jwk, supplementary kvm only for this unit, empty capability sets,
NoNewPrivileges, PrivateNetwork, 4096 MiB memory maximum, 1800-second maximum,
no restart and control-group teardown. Existing unit names are refused. Both
terminals stay attached; this is not unattended target execution.

## Actual controlled flow

Each group has a fresh one-vCPU/256 MiB parent, but both measured children ALWAYS
restore that parent's full RAM/CPU/device snapshot. A parent exits before either
child starts. New clean upper copies preserve captured disk contents separately
for each child, patched while paused before resume. Actual upper FDs are checked.

The Guest is controlled through serial stdin/stdout and FC's API, not a network
service. The matching FC source supports terminal/FIFO serial input. Token-bound
commands reject replayed serial lines from snapshot state. No target content is
read during boot, metadata checking or cold-state validation. The target file
is not a boot/helper dependency.

* B0: actual non-DAX lower and merged file; parent and child pre-read mincore
  must show zero data pages resident.
* B1: parent performs exactly one bounded 8 MiB read and SHA check; mincore must
  show every page resident at capture barrier and both child pre-read barriers.
* D0/D1: actual lower and merged file must be DAX; read counts distinguish the
  factor. DAX mincore is deliberately not used as ordinary-cache evidence.

The mincore checker uses a PROT_NONE mapping and does not touch target data.
It requires owner/CAP_FOWNER authority so Linux's permission-masked all-ones
response cannot silently pass the hot group. No target fadvise/drop_caches is
used to repair a failed cold condition. Wrong state stops the experiment.

Parent barrier syncs its private disk and rechecks cache state, then FC pauses
and creates a Full snapshot. A missing/unknown snapshot acknowledgement never
starts children and is not retried. Both children load the same immutable RAM
file; Guest region API + smaps prove MAP_PRIVATE, device/inode and offsets.
The parent RAM/state/disk bases are rehashed after child exit. No raw PFNs or
Guest contents are sampled by the Host observer.

For pmem the FC stores portable content references. Every child opens a fresh
Host FD, verifies its inode/size, and gets a new private content-rebinding file;
it does not reuse an exited parent's process-local FD identity.

Both children complete the pre-read barrier before Host pre-read sampling.
READ commands are released within a recorded <=100ms Host send window. This is
a common release barrier, not a promise of simultaneous CPU instruction timing.
Each child reads exactly 8 MiB once with a 64 KiB buffer and verifies the SHA.
Three one-second samples and a five-second hold follow. Children power off and
must exit0; all known FCs are reaped before the next group. Any group failure
stops the matrix and preserves artifacts. Unknown spawn outcomes remain unknown.

## Measurements and acceptance boundaries

Capture preparation, admission, each group before preparation, parent before
read/capture, parent captured/exited, both children before read, three post-read
holds and child exit. Record own-unit charge, Host meminfo, FC whole RSS/PSS,
actual Guest RAM VMAs, pmem RSS/PSS with backing identities, retained file sizes,
disk allocation/residency, private uppers and controller cost. All prior retained
group artifacts remain in the file ledger, exposing sequential-group carryover.
Missing required FC/RAM PSS or unit charge fails rather than inventing zero.

The experiment does not yet attribute the target's Guest pages through GPA to
stable Host PFNs. Physical net saving is therefore null even when all four groups
pass. Guest Cached, PSS, cgroup charge, RAM-base cache and pmem/file-cache overlap
must not be added into a claimed global total. Continuous hold samples are not
independent trials. The fixed order is disclosed; no positive gain is promised.

## Output and recovery

Return preparation.json, admission.json, return.json and the full terminal/root
receipt. journal.json and per-machine serial/stderr logs remain for diagnosis.
Source files, parent snapshots and all upper copies are explicitly retained.
Success: PCC_FOUR_GROUPS_PASSED_OWNED_GUESTS_RELEASED_NOT_PHYSICAL_NET_ACCEPTANCE.

Do not rerun prepare/run over prior state. `status` reads existing journal.
`recover` requires the controller lock to be free, verifies each known PID's
start ticks, executable and cwd, and uses pidfd to stop only those processes.
Missing spawn acknowledgements are not guessed; recovery does not delete files
or clear unknown intent, nor does it rerun any group. For any stopped result,
return the receipt before attempting a new run. The transient unit is bounded;
other services, users' groups, devices and permissions are not altered.

## Local validation

Guest helper cross-compiled successfully to static Linux ARM64 ELF. Local tests
exercise cold/hot refusal, no pre-read hashing, DAX evidence separation, snapshot
and parent-exit gates, shared/wrong RAM-base refusal, cleanup uncertainty and
bootstrap scope. API/Guest lifecycle is simulated locally. No local Linux KVM
or target Guest execution is claimed; first on-machine execution is still pending.
