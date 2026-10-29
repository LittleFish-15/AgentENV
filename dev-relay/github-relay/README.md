# AgentENV manual GitHub exchange v1

This is a user-triggered script/result exchange. Each invocation fetches the
current round, executes at most one assigned task, uploads the result, and exits.
There is no background polling, daemon, automatic next step, or model heartbeat.
The user says that execution is finished; the controller then reads results,
analyzes them and publishes the next round. The user invokes the same entry again.

## One-time setup

Reviewed code is distributed from LittleFish-15/AgentENV's experiment branch.
Private profiles, round queues and jobs live in a private control repository.
Registrations and results live in a separate private results repository.
Use a dedicated fine-grained Contents-read token for control and a different
Contents-write token for results. Enter them only at hidden interactive prompts.
They stay in a 0600 credential file in the enrolled user's private home state.
No desktop administrator token is distributed. Noninteractive token prompts
are rejected before getpass can fall back to echoed input.

Only ordinary Linux UID1204/GID1205 with zero Inheritable/Permitted/Effective/
Ambient capabilities is accepted. Enrollment binds host, machine and current
boot. Repository private visibility and identity are checked before uploads.
Nothing falls back to a public result channel.

## Reviewed tasks and scope

The initial round inventories A/B retained artifacts and obtains C/D identities.
The historical inventory source is fixed to Git blob
040068bd8ef9e85f9fac8073eab3cc6c51557c8d and SHA256
b0788d2683d3038dc85fa9b3892f183d5eaf0ca8597a6fc715ee763db4319658.
This does not start a service, execute the workload, create a Guest or allocate UB.

`reviewed-python-v1` can select the next reviewed Python script without changing
the fixed client. Its descriptor binds this source repository, an immutable
commit, a path under dev-relay/, Git blob, exact SHA256/length, node list, scope
and a bounded duration. Source bytes must match before execution. No arbitrary
shell command, URL, argv or environment is accepted. Optional input is bounded
JSON data in the private job directory, not interpolated into shell arguments.

Profiles restrict operation/scope by node. A/B roles permit read-only inspection
and approved immutable-source export; C/D roles permit read-only inspection and
approved work within their ordinary workspace. The current profiles enable
read-only scope. Reviewed task scripts remain responsible for validating their
specific input paths, budgets and effects; this is not an OS filesystem sandbox.
Root scope is not supported. Modules, mounts, system services and privilege changes
still need the user's separate concrete approval and corresponding reviewed tools.

## Manual round semantics

- One current round per node, with zero or one task. No task means immediate exit.
- A private local journal binds job ID, payload hash and node/boot identity.
- Repeating the command does not rerun an already uploaded job.
- Upload failure preserves a completed result. Repeating the same command retries
  upload only, rather than repeating the node operation.
- A journal left running after interruption produces an attention receipt and
  stops for reconciliation. It never silently retries or claims cleanup.
- Results are immutable. Identical existing bytes reconcile an upload ACK;
  different bytes stop without overwrite.
- A node lock prevents two concurrent invocations on the same enrollment.
- Logs have size/time limits, credential redaction and deterministic compression.
  Truncation is explicit; the original bounded logs remain local.
- Only the relay's own bounded child can be terminated for a read-only timeout
  or output limit. Mutating task scripts must implement their own confirmed
  lifecycle and must not treat interruption as successful rollback.

Each user invocation reads the latest approved profile and round once. It does
not wait for a new round. Publishing a later task does not start anything on a
machine until the user runs the fixed command there again.

## Node commands

After a one-time pinned installation:

```bash
bash /home/jwk/agent/github-relay/start.sh
```

The entry enrolls once if necessary, then executes one round and exits. Subsequent
calls reuse the two credentials. Keep the interactive terminal open only until
the current round finishes; no long-running terminal is required afterward.

The implementation commands are:

```bash
/usr/bin/python3 -I -B relay_runner.py enroll --control-repo OWNER/PRIVATE_CONTROL --result-repo OWNER/PRIVATE_RESULTS
/usr/bin/python3 -I -B relay_runner.py run
/usr/bin/python3 -I -B relay_runner.py status
```

Use the exact installed runner path shown by the installation. Boot identity
changes and unknown prior outcomes require explicit reconciliation. Do not remove
state to bypass the guard. The optional stop flag blocks a future manual call;
it performs no resource cleanup and is not silently cleared.

## Verification boundary

Local tests cover one-call/one-round return, no automatic future task, duplicate
calls, transfer-only retry, unknown interruption, source mismatch, node/boot/scope
binding, repository privacy, immutable result conflicts, log redaction and hidden
credential prompting. These do not constitute native target acceptance.
Actual A/B/C/D roundtrips and later UB/DAX/Guest/cache/savings acceptance are separate.
