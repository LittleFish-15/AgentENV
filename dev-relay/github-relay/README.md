# AgentENV read-only GitHub relay v1

This first version closes the task/result transport loop for ordinary-user
read-only inspections. It is not a generic shell agent, kernel deployment
agent, or hardware acceptance test.

## Separation and permissions

- Reviewed runner/source code is distributed from the existing experiment branch.
- Jobs/profiles/queues live in a **private control repository**. Node credentials
  need Metadata read and Contents read there.
- Registrations/results/attention receipts live in a **different private results
  repository**. A second node credential needs Metadata read and Contents write.
- Use dedicated fine-grained PATs, not desktop administrator credentials. Enter
  them through the hidden terminal prompts. They are saved only in the ordinary
  user's private state directory, with mode 0600. Do not paste them into chat,
  shell arguments, environment exports, scripts, commits, or reports.
- All runtime actions require Linux, real/effective UID1204, matching GID1205,
  the enrolled node identity, and zero Inheritable/Permitted/Effective/Ambient
  capabilities. Root execution is refused.
- Repository identity and private visibility are checked. Results are never
  redirected to a public repository when private upload fails.

The runner cannot create GitHub PATs for the user. Initial token creation and
starting the fixed entry once on each machine are onboarding steps. Subsequent
task and result transfers do not require copying terminal logs into chat.

## Supported operations

1. `retained-inventory-v1`, on node-a/node-b only: the already reviewed immutable
   inventory source, Git blob `040068bd8ef9e85f9fac8073eab3cc6c51557c8d`, SHA256
   `b0788d2683d3038dc85fa9b3892f183d5eaf0ca8597a6fc715ee763db4319658`.
   It inventories retained Runtime/FC/dependencies, selected snapshot metadata,
   memory layers, private replay identities and the existing container. It does
   not execute the replay, modify a service, allocate UB, or copy large payloads.
2. `identity-v1`: reports the enrolled ordinary-user node identity.

No arbitrary `command`, `argv`, `env`, script URL or root operation is accepted
in a job. A new operation needs a reviewed runner release and explicit scope.
The complete four-Guest launcher/controller is still separate unfinished work;
this relay does not turn a read-only inventory into a successful experiment.

## Local journal and retry behavior

- Private state defaults to `~/.local/state/agentenv-github-relay`.
- An OS file lock prevents two runners from executing on the same enrollment.
- Each job is bound to node, session, payload digest, current boot/machine/user
  identity and a valid time window.
- `running` is durably written before process launch. An interruption with an
  unresolved running journal uploads an attention receipt and stops. It never
  silently reruns the job or claims resource cleanup.
- A completed process produces a durable `upload_pending` result. Network
  failure retries only result upload, never the underlying operation.
- Remote results are immutable. Existing identical bytes reconcile a lost
  upload ACK; different bytes stop instead of being overwritten.
- Logs have explicit size/time limits, known-token redaction and deterministic
  compression. Truncation is reported, never hidden. The original logs stay local.
- v1 can terminate only its own bounded read-only child at timeout/output limit.
  This policy must not be reused for SDK allocation, Guest mutation or root work.

Task queues use conditional requests/ETags, approximately one-minute polling,
and bounded backoff. Results are uploaded at task boundaries. No per-second Git
commits, large images, snapshots or payload files are used as the control channel.

## Commands

After downloading the exact runner version and checking its published SHA:

```bash
/usr/bin/python3 -I -B relay_runner.py enroll --control-repo OWNER/PRIVATE_CONTROL --result-repo OWNER/PRIVATE_RESULTS
/usr/bin/python3 -I -B relay_runner.py run
```

Enrollment automatically selects a unique node from the private session profile.
The first command prompts for the two restricted tokens only on first enrollment;
later calls reuse the enrolled state. Existing identity mismatches are preserved,
not overwritten. A partial enrollment requires explicit reconciliation.

The first version runs in the foreground for up to 240 minutes, bounded further
by the session expiry. Keep that terminal open. No system service is installed.
The same fixed command can be used to restart after an ordinary disconnect;
the journal prevents repeated completed jobs. Unknown running jobs stop for review.

From another ordinary-user terminal:

```bash
/usr/bin/python3 -I -B relay_runner.py status
/usr/bin/python3 -I -B relay_runner.py stop
```

Stop is checked between read-only jobs; the current job is bounded by its own
timeout. It performs no resource cleanup. A persisted stop request is not
silently cleared by a later `run`. Do not delete state directories to bypass it.

## Verification boundary

Local tests cover wrong node/session/boot, arbitrary-command rejection,
source mismatch, duplicate jobs, lost upload ACKs, upload-only retry,
interruption reporting, private-repository enforcement, conflicting results,
identity selection and credential redaction/environment isolation.

These are logic/transport tests. Native Linux enrollment, filesystem permissions,
locking and the actual private GitHub roundtrip from each target still require
the first user-started node run. No Guest/UB/DAX or savings result is implied.
