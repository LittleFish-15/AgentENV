"""DSec-style ordinary Host-file provider for readonly Guest pmem/DAX rootfs.

Files must remain immutable for all consumers. No Host FS-DAX, SDK, persistent
memory hardware or cross-node physical-sharing claim is involved.
"""
from .fsdax import main

if __name__ == '__main__':
    main(host_pagecache=True)
