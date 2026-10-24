#!/agentenv/bin/busybox sh
BB=/agentenv/bin/busybox
fail() { echo 'PCC_EVENT {"event":"error","error":"guest init failed"}'; $BB poweroff -f; exit 1; }
$BB mkdir -p /proc /sys /dev /mnt/ro0 /mnt/write /mnt/user || fail
$BB mount -t proc proc /proc || fail
$BB mount -t sysfs sysfs /sys || fail
if ! $BB awk '$2=="/dev" && $3=="devtmpfs" {v=1} END {exit !v}' /proc/mounts; then
 $BB mount -t devtmpfs devtmpfs /dev || fail
fi
MODE= SHA=
for arg in $($BB cat /proc/cmdline); do
 case "$arg" in
  pcc_mode=*) [ -z "$MODE" ] || fail; MODE="${arg#pcc_mode=}" ;;
  pcc_sha=*) [ -z "$SHA" ] || fail; SHA="${arg#pcc_sha=}" ;;
 esac
done
case "$MODE" in block|pmem) ;; *) fail ;; esac
[ "${#SHA}" = 64 ] || fail
waitdev() { n=0; while [ ! -b "$1" ] && [ "$n" -lt 30 ]; do $BB sleep 1; n=$((n+1)); done; [ -b "$1" ]; }
waitdev /dev/vdb || fail
$BB mount -t ext4 -o rw /dev/vdb /mnt/write || fail
$BB mkdir -p /mnt/write/.pcc/upper /mnt/write/.pcc/work || fail
if [ "$MODE" = block ]; then
 waitdev /dev/vdc || fail
 $BB mount -t ext4 -o ro,noload,nodax /dev/vdc /mnt/ro0 || fail
else
 waitdev /dev/pmem0 || fail
 $BB mount -t ext4 -o ro,noload,dax=always /dev/pmem0 /mnt/ro0 || fail
fi
$BB mount -t overlay overlay -o lowerdir=/mnt/ro0,upperdir=/mnt/write/.pcc/upper,workdir=/mnt/write/.pcc/work /mnt/user || fail
# No target content read, hash, cat, or prefetch occurs before the controller READ.
$BB stty -F /dev/ttyS0 -echo || fail
exec /agentenv/pcc-helper "$MODE" "$SHA" </dev/ttyS0 >/dev/ttyS0 2>&1
