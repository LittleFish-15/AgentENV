# Scoped recovery and separate full-UB delete-fix deployment

Root entry: AB_recover_stage_deletefix_OFFLINE_root.sh, 47942 bytes,
SHA256 `d85f7fd78b8fb93640444ef7be0c4b8a33c871220c7cab437d064b130122dba4`. Same code supports A/server1 and B/agent1;
start with A. On B the verified daemon must first be copied manually, as jwk,
to `/home/jwk/agent/uvm-ublk-daemon-private-delete-v1`.

Daemon artifact: 24758576 bytes, SHA256
`5291c267777cd91c4b853c6d40720e8d87200b2a0162024782534c4126cba726`.
A source: `/home/jwk/agent/builds/ub-private-delete-daemon-resume-v2/artifacts/uvm-ublk-daemon`.
Only this daemon needs transfer. Do not rebuild B, transfer credentials/reports,
or introduce a new remote execution/transport mechanism.

## Exact effects and gates

Use root in a maintenance window for this dedicated experiment unit only. The
entry locks the existing pair, checks the fixed old launcher/binaries/provider,
exact known cohort and phase (A pending release-a; B peer-isolated), exact local
API ownership, FC identity and daemon device ownership. The rootfs ID comes
from the actual ready report; the sole shared memory ID must come from this
Guest's creation log. Any additional/unknown device or FC refuses the operation.
The provider must be outside the unit cgroup. New artifact, paths and unit must
pass preflight before any signal.

Small stable upper/config bytes and old journals are copied into a new private
`acceptance/direct-pair-v1/deletefix-recovery-v1` directory. This is byte evidence,
not a VM snapshot or a promise to restore a terminated Guest. Then one SIGTERM
is sent through a verified pidfd to the old Runtime main process. Its existing
shutdown code drains the daemon's managed, active-exclusive, shared and idle
device registries. No manual device ioctl, module load, reboot or hotplug is
used. There is no SIGKILL fallback. Process exits, all two owned block/char/sysfs
devices absent, and empty old cgroup must be observed within 90 seconds; otherwise
stop with evidence and no deployment. The matching old host proxy is then
stopped by pidfd SIGTERM, and local provider reader/response counts must reach
zero. Provider process, object generation and protected units must remain stable.

Old pair state.json, report.json and pair-phases.json are checked unchanged.
Their failed DELETE is not changed to a successful API result, and this run is
not marked as a normal lifecycle pass. No SDK object is retired. The core fix's
normal Delete path still requires a fresh actual Guest regression.

Only after verified drain does the entry stage the separate deployment:
`/home/jwk/agent/deployments/agentenv-direct-ub-deletefix-v1`;
runtime `r/dgf-a-v1` or `r/dgf-b-v1`, FC workspace `r/dff-a-v1` or `r/dff-b-v1`;
unit `jwk-aenv-direct-ub-deletefix-v1-node-a.service` or `node-b.service`.
It reuses the old exact localhost API port, never chooses an additional port.
The unchanged server/CLI/FC/kernel/tools and existing eight UB objects are reused.
The old deployment and artifacts are not overwritten; immutable snapshot sources
are bound read-only inside the new private mount namespace, not copied wholesale.
The already reviewed User/Group, capabilities and private network/mount setup are
retained. No external port, SSH/SFTP, cross-node coordinator or new SDK client is
started. Actual server/daemon identities, hashes and ordinary-user health are
checked. No new Guest is created by this entry.

## Outputs and stop conditions

Success: SCOPED_OLD_RUNTIME_RECOVERED_DELETEFIX_HEALTHY_NO_GUEST.
Return BEGIN_SCOPED_DELETEFIX_RECOVERY_REPORT through
END_SCOPED_DELETEFIX_RECOVERY_REPORT. Progress and private prepare.log/health.log
stay in the recovery directory. A's success also records the exact file to
transfer to B. Run B only after A succeeds and the daemon file is in place.

Any unknown identity, failed drain, changed source/journal, staging or health
failure stops. Do not rerun an attempt after its recovery directory exists.
There is no automatic retry, forced kill, restart, cleanup or rollback. If the
new service has no Guest and the new cohort is still exactly prepared, its fixed
`AB_deploy_direct_deletefix_v1.py stop-empty --run` mode is the scoped stop path.
It is not a pending-Guest recovery command. The old deployment is preserved for
inspection/reproduction, but the old failed Guest is not automatically resumed.

Server build source remains ff1efdd9; the daemon fix source is d97d2388. The
combined deployment records both and pins their actual hashes. Full mode and
pmem/demand branches are retained. Local guard/config/drain-loop checks use
doubles; actual signals, kernel cleanup, deployment and new Guest lifecycle are
not claimed until their target receipts return.
