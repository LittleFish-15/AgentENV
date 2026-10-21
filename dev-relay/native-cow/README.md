# Native CoW experimental relay

Latest: A_rootfs_compare_ext4_v2.py --run (ordinary experiment account).
Reuses the pinned, already downloaded rootfs_cache_compare.py packet. Verifies
the prior run stopped at ext4 Unknown parameter nodax, all FCs were reaped and
leases closed. Prepares a new cache-compare-v2 stage and new v2 unit; preserves
all v1 files. The only Guest semantic change is block lower mount options from
ro,noload,nodax to ro,noload,dax=never, supported by Linux 6.1 ext4. Negative DAX
statx checks remain mandatory. No SDK call, existing service change, filter
change, new UB allocation or automatic retries. Review and paste printed root
block to run four matched block/pmem N=1/2 groups.

This measures synthetic cold-boot rootfs Guest cache and scoped Host charge.
It does not measure original snapshot CoW, memfile private CoW or global
cross-node net savings. UB stays alive outside the measurement unit in both
modes. Unknown and signed results are retained.

The original comparison packet contains the project-built Guest statx helper
and its Go source. No credentials, private workload or captured measurements
are included. Core and main remain unchanged. Earlier scripts are retained for
provenance; do not rerun completed cases.

Repair SHA256: 91614a2a00647f989eb3448cf5f57191b3cf7d05df0f3033aa6e44e973419e99
