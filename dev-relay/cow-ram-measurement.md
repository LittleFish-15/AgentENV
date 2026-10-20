# Scoped live Guest RAM and cache observation

The previous original pair restored successfully and verified private-file
isolation. Its process collector failed before reading smaps because it assumed
the cgroup v2 system.slice mount. This change walks only the original Runtime's
descendant tree, including children created by non-main threads. It never scans
all host processes or reads command lines/environments.

The two previous Guests have exited. The next launcher restores exactly two new
measurement Guests from the retained 512-MiB parent; it does not rebuild the
parent or repeat the private-file test. Existing root access is used only for the
metadata observation below, without capabilities/ACL/device changes.

## Ordinary user workflow

On A/server1 as jwk, place `cow_ram_pair.py` and `cow_ram_readonly.py` in
`/home/jwk/agent`. The already delivered `cow_parent_424b012.py` is also required.
The launcher checks the two helper hashes before importing them.

Run `python3 -I -B cow_ram_pair.py`. It checks ordinary identity/capabilities,
parent resources, empty API inventory and absence of existing Firecracker
descendants. It restores at most two children with a 900-second TTL, imports
pypika, and prints the complete inline root command with fixed PID/start-time,
sandbox IDs, Runtime identity, boot ID and parent catalog hash.

Keep that terminal open. In the existing A root terminal, paste **only** the body
between the printed BEGIN/END command markers. No root execution of a
jwk-writable script file is requested: the command contains the reviewed source
and the literal scope, using `python3 -I -B -` and standard-library modules.
After that command exits, return to the jwk terminal and type `done`. The
launcher deletes only children with this run's ownership metadata, verifies 404,
and removes temporary CLI credentials. Its wait is bounded at 600 seconds.
Unknown create outcomes are retained, not retried or arbitrarily deleted.
Return **both** the root measurement report and the jwk cleanup report. `done`
does not prove measurement success; only the root report provides that evidence.

## Exact administrator read scope

- `systemctl show` for `jwk-aenv-ae9c626-node-a.service` only;
- current boot ID and the selected Runtime/child proc identity metadata;
- for two selected Firecracker PIDs: status, stat, cwd/FD links, relevant FD
  flags, smaps, and pagemap only over the validated Guest RAM mappings;
- `/proc/kpageflags` only at page-frame offsets obtained from those mappings
  (bounded nearby slots are read in small batches, only requested flags used);
- selected sandbox Firecracker log for its File memory backend, plus the
  hash-pinned parent catalog and each selected sandbox's overlaybd image config;
- read-only mincore of that memory device, the actual open rootfs device, their
  owned upper files, the runtime's actual local lower references within this
  deployment's state, and the catalog's managed layer files. Block sizes come from
  their own `/sys/class/block/ublkbN/size`; no guessed ioctl/syscall numbers.

No API key, /proc/pid/mem, command line, environment, Guest memory contents or
raw PFNs are output. No device data is read/faulted by the collector. It performs
no service management, writes, permission changes, cache eviction, mounting,
process signals to Guests or SDK calls. It only prints results to stdout. A
120-second self-deadline ends sampling; it does not kill any other process.

## Attribution and arithmetic

The collector requires one-to-one child PID ↔ own stderr log sandbox ID binding
and ancestry under the same original Runtime. It extracts the actual File
backend from that sandbox's snapshot-load log, selects private VMAs matching the
device path and requires total VMA coverage to equal 512 MiB. It does not choose
an arbitrary anonymous mapping merely because its size resembles Guest RAM.
Wrong format, missing identity, hidden PFNs and incomplete coverage stop the RAM
claim. CoW anonymous pages inside these file VMAs remain in Guest RAM accounting.

For two selected consumers, each process first deduplicates aliases by PFN:

- unique RAM = |P1 union P2| × actual host page size;
- shared unique RAM = |P1 intersection P2| × page size;
- shared participating RAM = 2 × shared unique RAM;
- avoided duplicate RAM = shared unique RAM;
- participation ratio = shared participating RAM / (|P1| + |P2|) / page size;
- duplicate avoidance ratio = shared unique RAM / (|P1| + |P2|) / page size.

Zero/KSM/compound-or-huge/ordinary-file/ordinary-anonymous/unclassified pages are
reported separately. The ordinary snapshot-file claim additionally requires the
pagemap file bit to agree in every selected consumer. Compound attribution is
explicitly incomplete. Three observations compare pagemap identity before and
after the flags read; unstable observations must be rejected. Samples remain
non-atomic, and even stable endpoints do not prove an atomic stop-the-world view.
PFNs are not used across different nodes.

The same observation records memory-device cache, each rootfs-device cache,
upper file allocation/cache, and stored layer file cache. O_DIRECT is read from
the actual rootfs device FD flags. Unavailable mincore stays unavailable, not
zero. These cache byte counts are not automatically added to Guest RAM: memory
device cached pages can already be the Guest's file-backed physical pages.

This batch establishes live baseline observations. Controlled RAM first-write,
repeat-write, multi-generation, colleague replay and modified/cross-node UB
comparisons remain required; this script does not mark full CoW acceptance.

Local tests: `python3 -I -B dev-relay/test_cow_ram_measurement.py` and
`python3 -I -B dev-relay/test_cow_pair_once.py`. Synthetic identities, PFNs and API
responses do not validate target kernel behavior or actual memory savings.
