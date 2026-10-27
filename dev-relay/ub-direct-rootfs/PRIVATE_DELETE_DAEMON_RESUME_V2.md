# Resume the reviewed pre-daemon-build tuple failure

Use A_resume_private_delete_daemon_v2_OFFLINE_jwk.sh as ordinary jwk on A/server1.
It embeds the fixed resume program; no network access is used. Core commit stays
 d97d2388e6985e7d28faa3746b91fe54c18aaf60. The defect was the missing trailing comma
around the one-item build tuple, not a failure of the four native registry tests.

The retained A_build_private_delete_daemon_v1.py must match SHA256
7c280363779db70b8fa9b2a4aa45fd849830797ca7de933b3352ce9d144448c1.
Its pinned input constants are read with ast.literal_eval; the failed program is
not executed again. The resume body has its own embedded digest.

Before continuing, require exactly the reviewed ValueError failure, the same
source release, four named successful native test log records, no pending build
phase, no rebuilt component/capture and an empty prior artifacts directory.
Verify all 878 tested source files against their pinned hashes. Reuse the source
in builds/ub-private-delete-daemon-v1/source and the existing dependency target.
Do not copy or modify the old source, delete its output, or rerun cargo test.

New logs/progress/artifacts go to builds/ub-private-delete-daemon-resume-v2.
The actual daemon build loop is corrected to contain one four-field tuple.
Capture the linked binary before Cargo unlocks, then verify artifact provenance,
unchanged source and retained full binaries. The old test duration is recorded
under resumedFrom, not counted as a test executed by this invocation.

Expected progress: REUSED=verified-native-private-delete-registry-tests, then
PHASE=build-uvm-ublk-daemon. Return BEGIN_PRIVATE_DELETE_DAEMON_RESUME_REPORT
through END_PRIVATE_DELETE_DAEMON_RESUME_REPORT. Success is still
UB_PRIVATE_DELETE_DAEMON_BUILT_TESTED_NOT_DEPLOYED. Failure preserves both old
and new directories; do not restart or clear an uncertain attempt.

This does not deploy, reconcile the pending Guest release, call SDK, touch a
kernel/module, start/stop Guests or change services. Old server, FC, provider,
objects and original full artifacts remain. A native daemon SHA is still needed
before a matched recovery/deployment step can be finalized.

Local checks execute the original failing loop and the full corrected loop with
a fake compiler, check failure/test guards and verify embedded bytes. They are
not native compilation or kernel deletion tests; the actual native test pass is
from the user's prior report and is revalidated against target logs at resume.
