# Native DSec restore authentication-order update

This updates only the isolated A Runtime after the observed secure restore
failure. Native DAX/executable readiness checks ran before the normal envd init,
while the restored envd still carried the source instance's authentication
state. The core fix moves those checks after init; it does not disable secure
mode, reuse the parent's token, suppress401, relax DAX checks or extend Guest
command timeouts. Normal rootfs initialization/notification order is unchanged.

Core: `2c2c0ea573f97a0ce8fc64f2dfb79d60b7089a14`.
The actual old readiness method reproduces the ordering failure in a local
model; the fixed method passes5 ordering/failure tests. Full ARM64 check--tests
passes, including a real loopback HTTP init-before-RPC regression in the core
test code. The loopback core test was compiled, not executed on the target.
Local integration checks simulate API/systemd/process metadata; no target
Guest or UB acceptance is claimed by those checks.

## One coordinated entry

`A_dsec_auth_order_and_restore_v1.py` supports:

- `prepare`: verify retained offline sources, build only server and run the
  actual-method readiness contract, reconcile the exact failed restore,
  preserve its journal and successful snapshot, and stage coherent metadata.
- `activate --plan-sha ...`: run only the printed root block. Retire the exact
  previous experimental Runtime/cgroup, owned proxy and Host-file provider;
  preserve unrelated services; then atomically apply known files, start the
  candidate and check health. Root verifies the proxy's pidfd/start time,
  precise command line and credentials before signalling it.
- `validate`: restore two children from the already captured successful
  template, verify DAX/exec73 and the captured upper marker, check copy-up
  isolation, delete the writer and recheck the surviving peer, then clean up
  registered children. No new cold start or catalog capture is performed.
- `recover`: only reconcile the new validation's owned IDs. Unknown POSTs are
  retained and never implicitly retried.
- `status` / printed root `rollback`: inspect or explicitly restore the
  scoped before-files; unknown file versions and unconfirmed live resources
  block rollback. The restored experimental service remains stopped.

The old failed run is in `dsec-real-template-smoke-v2`; it is preserved. The new
validation uses `dsec-real-template-smoke-v3`. New build and update directories
are `builds/dsec-auth-order-fix-v1` and `updates/auth-order-fix-v1`; prior build,
metadata backup, first-failure retirement proof and all snapshots remain.
The current installed Runtime must match the returned PID/start/config/boot
and original built server pin before activation is prepared.

Expected flow: A ordinary `prepare` -> A root printed activation -> A ordinary
`validate`. The positive functional result is
`DSEC_RETAINED_RESTORE_PAIR_PASSED_GUESTS_RELEASED`.
If any step fails, return its bounded report and preserve all files; do not run
the four-template entry, restart earlier validation runs or delete pending
journals. The exact failed Guest may be deleted once only when metadata and
inventory prove this run owns it. API404 alone never clears the pending request:
the full owning Runtime retirement evidence is still required.

This is a prerequisite fix for the DSec path. It is not a two-node demo or a
memfile private-CoW implementation. Four-template expansion stays deferred until
the separately required cross-node core paths are established. No B connection,
SDK call, kernel/OBMM/module change, reboot or cache eviction occurs here.
