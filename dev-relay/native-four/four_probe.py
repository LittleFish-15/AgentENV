"""Inspect the static DAX execution marker; does not execute it."""
import hashlib, struct

def need(ok, reason):
    if not ok:
        raise RuntimeError(reason)

def inspect_probe(data):
    need(64 <= len(data) <= 1024**2 and data[:6] == b'\x7fELF\x02\x01', 'Expected bounded little-endian ELF64')
    need(data[6] == 1 and struct.unpack_from('<I', data, 20)[0] == 1, 'Unsupported ELF version')
    need(struct.unpack_from('<HH', data, 16) == (2, 183), 'Expected static AArch64 executable')
    entry, phoff = struct.unpack_from('<QQ', data, 24)
    phentsize, phnum = struct.unpack_from('<HH', data, 54)
    need(phoff >= 64 and phentsize == 56 and 0 < phnum <= 16 and phoff + phnum * phentsize <= len(data), 'Invalid program headers')
    entries = []
    for i in range(phnum):
        kind, flags, offset, va, _, filesz, memsz, align = struct.unpack_from('<IIQQQQQQ', data, phoff + i * phentsize)
        need(kind != 3, 'Interpreter dependency is not allowed')
        if kind == 1:
            need(not flags & 2 and offset + filesz <= len(data) and filesz <= memsz, 'Writable or invalid load segment')
            if flags & 1 and va <= entry < va + filesz:
                entries.append(offset + entry - va)
    need(len(entries) == 1, 'Unique executable entry required')
    instructions = data[entries[0]:entries[0] + 12]
    need(instructions == struct.pack('<III', 0xd2800920, 0xd2800ba8, 0xd4000001), 'Probe is not exactly exit(73) at entry')
    return {'machine': 'aarch64', 'entry': entry, 'expectedExit': 73, 'bytes': len(data),
            'sha256': hashlib.sha256(data).hexdigest(), 'hostExecuted': False, 'GuestExecuted': False}
