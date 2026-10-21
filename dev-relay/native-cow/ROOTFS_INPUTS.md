# Original rootfs input reuse for the coordinated deployment

`native_rootfs_inputs.py` provides `pack`, `receive` and `seed`. Each mode is
plan-only unless `--run` is supplied. This is input preparation, not a UB
publication, Guest run, memory-saving measurement or RAM CoW implementation.

The input selector is the already reviewed `A_export_real_rootfs_v1.py`, checked
against its fixed SHA256. It selects the original 12 immutable layers only after
matching the retained parent receipt, snapshot catalog and recorded inventory.
The captured writable delta is excluded by the verified ordered-prefix check.
The original OCI manifest/config and all 12 compressed OCI blobs are included.
The archive does not contain the old Runtime database, API keys, running state
or private benchmark traces. Archive data stay in the user's environment; only
the helper source is published in this branch.

`pack --archive NEW_FILE --run` runs on A and prints the archive SHA256. The
caller transfers that file. `receive --archive FILE --sha256 PIN --destination
NEW_DIRECTORY --run` validates the archive, exact regular-file inventory,
content hashes, ordered layer identity and complete OCI blob references. Existing
destinations and partial outputs are preserved rather than silently reused.

After service preparation, before the new Runtime has ever started, use
`seed --input-directory RECEIVED_DIRECTORY --node node-a|node-b --run`.
It holds the same cohort lock as the deployment controller, requires the new
unit to be absent and the cohort journal untouched, and verifies the deployment
definition. It creates the default new image cache from the exact selected
commit bytes and writes a source config containing their new paths. It copies
neither RocksDB nor cached runtime metadata. Normal Runtime resolution reads
the original OCI config to recover image metadata.

The seed receipt is
`/home/jwk/agent/deployments/agentenv-native-6cdac56/rootfs-inputs.json`.
It contains the exact `ociReference` for subsequent cold creation, the source
identity and derived config SHA256. Use this reference instead of reconverting
an arbitrary image and assuming its resulting base matches the pmem binding.

With a native binding, the updated `prepare_native_service_v4.py` activation
block requires a successful matching seed receipt before starting the service.
The intended order is service file preparation, input seeding, then activation.
An explicit `--ordinary-only` control service is exempt from this native gate.

Hashing/copying reads all selected inputs during preparation and can populate
Host page cache. The receipt explicitly makes no cold-cache claim. Keep this
preparation outside the workload sampling window; never turn its whole-file
residency into a sharing-benefit measurement.

Local validation: seven data-fixture tests cover pack/receive/seed, preserving
ordered identity and original bytes, rejecting mutable uppers, wrong order,
special backing, missing OCI content, wrong archive hashes, existing caches,
active units and pending requests. Two additional activation-gate tests exercise
the generated root code's seed checks. Linux ownership/flock, real OverlayBD
reads, Runtime cache-hit behavior and Guest cold start still require target
validation. Fixtures contain synthetic bytes, not executable Guest images.
