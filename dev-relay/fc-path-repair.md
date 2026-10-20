# Temporary A original Runtime repair

This relay helper is specific to the experimental deployment. It is not an
upstream installation requirement or part of the UB implementation.

The observed Firecracker API socket pathname was 114 bytes. The approved short
work directory produces a 65-byte example pathname. The missing stderr means
other causes of the early process exit have not yet been excluded.

The user approved exactly three original Runtime settings and one restart of
`jwk-aenv-ae9c626-node-a.service` after confirming its sandbox inventory is empty:

- `work_dir = "/home/jwk/agent/r/fc-a-base"`
- `serial_dir = "/home/jwk/agent/deployments/agentenv-ae9c626-baseline/logs/firecracker"`
- `log_level = "Info"`

On A/server1 as ordinary jwk, from `/home/jwk/agent`, run the downloaded helper:

```bash
python3 -I -B fix_original_fc_path.py --apply-reviewed
```

It checks both existing APIs, identities, the original all-state sandbox inventory,
and the installed Firecracker CLI before applying the config. It saves the prior
config and a receipt in its own report directory. Unknown custom settings stop
the operation. It never restarts a service itself.

After `A_ORIGINAL_FC_PATH_CONFIG_APPLIED_RESTART_REQUIRED`, copy only the body
between `BEGIN_REVIEWED_ROOT_COMMANDS_COPY_BODY_ONLY` and
`END_REVIEWED_ROOT_COMMANDS_COPY_BODY_ONLY` into the A root terminal. This is
inline standard-library code, not execution of a jwk-writable script as root.
It checks the exact config hash, original PID/start time, unit identity/isolation,
and empty inventory immediately before one exact-unit restart. A second execution
cannot pass the old PID/start-time guard after a successful restart.

Return to the ordinary A jwk terminal:

```bash
python3 -I -B fix_original_fc_path.py --verify
```

Expected result: `A_ORIGINAL_FC_PATH_RESTART_VERIFIED`, three HTTP204 samples from
both APIs, original process changed, modified process unchanged, and empty
original sandbox inventory. Return the complete BEGIN/END report. Failures stop;
do not repeat a restart or remove the parent preparation pending receipt.

The helper creates only its report/lock/receipt, the two approved directories and
the backed-up config replacement. It does not call the UB SDK, create a Guest,
touch B, or delete failed runtime directories. A successful health report does
not establish that a Guest starts or CoW works. The previous HTTP500 create
requires reconciliation before a new attempt. Config backups are retained;
rollback is not performed automatically because it would require another restart.

Local control tests (no target hardware/service verification):

```bash
python3 -I -B dev-relay/test_fc_path_fix.py
```
