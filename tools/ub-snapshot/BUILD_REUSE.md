# Reuse original AgentENV build dependencies

The UB feature retains the baseline Cargo.toml and Cargo.lock. Original dependency
sources can be reused; the modified runtime still requires rebuilding.

The build entry reads the historical vendor pointer, the original A build report,
and a bounded inventory under /home/jwk/agent. A vendor is accepted only if its
manifest identifies the baseline lockfile, then Cargo uses the existing directory
source in frozen mode. The old directory is not modified by this script.

Without that vendor, existing Cargo homes under the experiment root are inspected
for .crate archives. Only crates.io packages in the current lockfile are copied,
with their exact lockfile SHA256 verified. Copies are published atomically into
already existing registry cache slots of the new owned build cache. Old Cargo
configuration, credentials, Git checkouts and compiled target directories are not
copied. Existing destination files are preserved. No old caches are hardlinked.

The preceding partial download already initialized the new registry cache. If no
destination namespace exists yet, archive seeding reports zero destination slots
instead of inventing registry configuration. Existing vendor discovery still
works. Missing dependencies can be downloaded only when --allow-locked-network is
explicitly supplied. There is no automatic mirror change or toolchain install.

On A/server1 as ordinary jwk, after updating the existing clone to the reviewed
feature commit:

```bash
cd /home/jwk/agent/src/agentenv-ub-0118ebb &&
python3 -I -B tools/ub-snapshot/build_offline.py --allow-locked-network
```

EXISTING_INPUT_REUSE and the final report list the selected vendor, or discovered
old Cargo homes, copied archive count/bytes and skipped corrupt archives. Zero
copies does not prove old dependencies never existed: they may be absent now,
already present in the new cache, or outside the bounded inventory. Return the
complete report and automatic error tail if it fails. B waits and will use A's
completed artifacts. This step does not start a service, call the UB SDK, or create
a Guest/ublk device.

Local checks execute cache copying, checksum rejection, destination preservation,
original-file independence, interrupted-copy cleanup, configuration exclusion,
vendor discovery from old reports and existing environment regressions. The
symlink test is skipped on Windows where creation needs extra privileges. These
are local control checks, not evidence that a remote cache is present or that the
full target build passed.
