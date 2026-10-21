# Isolated NC device verifier

Build with `cargo build --locked --release --target aarch64-unknown-linux-gnu`.
Deploy as a new immutable executable and put its actual SHA256 in the native
rootfs device-runtime binding. This component is run by AgentENV with zero
capabilities; it is not a standalone SDK allocator or Guest test.

The verifier duplicates inherited segment FDs 64..95, requires readonly `O_SYNC`
character backing, maps all segments into one owned 2MiB-aligned address range,
and hashes the complete image. The parser and mapper are shared with the FC
patch source. It does not reopen a path. FD 42 is the provider lease, retained until
exit. Core dumps are disabled in the child. A fault or mismatch fails the launch;
no signal recovery or copy fallback is used. Full hashing is preparation work.
