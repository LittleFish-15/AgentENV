#!/usr/bin/env python3
"""Read only explicitly identified experiment PIDs and regular cache files.

No discovery of unrelated processes, Guest creation, SDK, service changes,
permission changes, cache dropping, full-file reads or automatic elevation.
"""
import argparse
import base64
from collections import Counter
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import time
import zlib


def read_json(path):
    with Path(path).open('rb') as stream:
        value = stream.read(2 * 1024 * 1024 + 1)
    if len(value) > 2 * 1024 * 1024:
        raise ValueError('Input metadata exceeds 2MiB')
    return json.loads(value)


def ticks(pid):
    data = Path(f'/proc/{pid}/stat').read_text()
    return int(data[data.rfind(')') + 2:].split()[19])


def rollup(pid):
    values = {}
    for line in Path(f'/proc/{pid}/smaps_rollup').read_text().splitlines():
        match = re.fullmatch(r'(Rss|Pss|Private_Clean|Private_Dirty|Shared_Clean|Shared_Dirty):\s+(\d+) kB', line)
        if match:
            values[match[1] + 'Bytes'] = int(match[2]) * 1024
    if set(values) != {name + 'Bytes' for name in ('Rss', 'Pss', 'Private_Clean', 'Private_Dirty', 'Shared_Clean', 'Shared_Dirty')}:
        raise ValueError('Incomplete process rollup')
    return values


def page_sets(pid, ranges, page):
    pages = sum((end - start) // page for start, end in ranges)
    if pages > 2 * 1024 * 1024:
        raise ValueError('Selected RAM exceeds 2 million pages per Guest')
    with Path(f'/proc/{pid}/pagemap').open('rb', buffering=0) as stream:
        result = set()
        present = 0
        swapped = 0
        for start, end in ranges:
            for address in range(start, end, page * 4096):
                count = min(4096, (end - address) // page)
                stream.seek(address // page * 8)
                data = stream.read(count * 8)
                if len(data) != count * 8:
                    raise ValueError('Short pagemap read')
                for (entry,) in struct.iter_unpack('=Q', data):
                    swapped += bool(entry & (1 << 62))
                    if not entry & (1 << 63):
                        continue
                    present += 1
                    pfn = entry & ((1 << 55) - 1)
                    if not pfn:
                        raise PermissionError('Present PFNs masked; cannot report zero sharing')
                    result.add(pfn)
        return result, present, swapped


def exclude_non_base(pfns):
    """Filter zero/KSM pages; reject huge/compound accounting until supported."""
    selected = set()
    excluded_zero = excluded_ksm = 0
    with Path('/proc/kpageflags').open('rb', buffering=0) as stream:
        for pfn in sorted(pfns):
            stream.seek(pfn * 8)
            data = stream.read(8)
            if len(data) != 8:
                raise ValueError('Short page flags read')
            flags = struct.unpack('=Q', data)[0]
            if flags & ((1 << 15) | (1 << 16) | (1 << 17) | (1 << 22)):
                raise ValueError('Compound/huge pages require a different physical accounting method')
            if flags & (1 << 24):
                excluded_zero += 1
            elif flags & (1 << 21):
                excluded_ksm += 1
            else:
                selected.add(pfn)
    return selected, excluded_zero, excluded_ksm


def sharing(sets, page):
    counts = Counter(pfn for values in sets for pfn in values)
    total = sum(len(values) for values in sets)
    shared = {pfn: count for pfn, count in counts.items() if count > 1}
    participation = sum(shared.values())
    avoided = total - len(counts)
    return {'selectedResidentParticipationBytes': total * page,
            'selectedUniquePhysicalBytes': len(counts) * page,
            'sharedUniqueBytes': len(shared) * page, 'avoidedDuplicateBytes': avoided * page,
            'sharedParticipationRatio': participation / total if total else None,
            'avoidedDuplicateRatio': avoided / total if total else None,
            'scope': 'selected_Guest_RAM_on_one_node_excludes_zero_and_KSM',
            'memfileOnlyBytes': None,
            'note': 'Guest RAM identity is caller supplied; PFNs do not by themselves identify a memfile base'}


def cache_file(entry, page):
    if (set(entry) != {'path', 'sha256', 'bytes', 'kind'}
            or entry['kind'] not in ('memoryLower', 'rootfsLower', 'upper')
            or re.fullmatch(r'sha256:[0-9a-f]{64}', entry['sha256']) is None
            or type(entry['bytes']) is not int or not 0 < entry['bytes'] <= 2 * 1024**3):
        raise ValueError('Invalid bounded regular-file cache input')
    path = Path(entry['path'])
    if not path.is_absolute():
        raise ValueError('Cache input must be absolute')
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size != entry['bytes']:
            raise ValueError('Only matching regular-file cache ranges are supported; not device cache')
        if before.st_uid != os.geteuid():
            raise PermissionError('File ownership does not establish an unmasked mincore result')
        length = before.st_size
        count = (length + page - 1) // page
        libc = ctypes.CDLL(None, use_errno=True)
        libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
        libc.mmap.restype = ctypes.c_void_p
        libc.mincore.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
        libc.mincore.restype = ctypes.c_int
        libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        libc.munmap.restype = ctypes.c_int
        address = libc.mmap(None, length, 0, 1, fd, 0)  # PROT_NONE, MAP_SHARED; no touching.
        if address == ctypes.c_void_p(-1).value:
            raise OSError(ctypes.get_errno(), 'Readonly cache inspection mmap failed')
        try:
            vector = (ctypes.c_ubyte * count)()
            if libc.mincore(address, length, vector):
                raise OSError(ctypes.get_errno(), 'mincore failed')
            bits = bytes(value & 1 for value in vector)
        finally:
            if libc.munmap(address, length):
                raise OSError(ctypes.get_errno(), 'Inspection mapping did not unmap')
        after = os.fstat(fd)
        identity = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)
        if identity(before) != identity(after):
            raise ValueError('Cache file changed during inspection')
        return {'sha256': entry['sha256'], 'kind': entry['kind'], 'fileBytes': length,
                'dev': before.st_dev, 'inode': before.st_ino, 'allocatedFileBytes': before.st_blocks * 512,
                'residentPages': sum(bits), 'residentBytes': sum(bits) * page,
                'offsetBitmapZlibBase64': base64.b64encode(zlib.compress(bits)).decode(),
                'identityRehashedDuringSampling': False,
                'note': 'Digest is committed input metadata; no full-file read or cache warming performed'}
    finally:
        os.close(fd)


def collect(config):
    if sys.platform != 'linux':
        raise RuntimeError('Live collection requires Linux; report generation is portable')
    if (set(config) != {'version', 'experimentId', 'nodeId', 'variant', 'phase', 'guests', 'files'}
            or type(config['version']) is not int or config['version'] != 1
            or config['variant'] not in ('original', 'modified-off', 'stored-ub', 'native-combined')
            or not 1 <= len(config['guests']) <= 8 or len(config['files']) > 256):
        raise ValueError('Invalid scoped collection config')
    page = os.sysconf('SC_PAGE_SIZE')
    output = {key: config[key] for key in ('version', 'experimentId', 'nodeId', 'variant', 'phase')}
    output.update(startedNs=time.time_ns(), pageBytes=page, guests=[], files=[], issues=[],
                  sdkCalled=False, guestCreated=False, globalUniquePhysicalBytes=None,
                  directMemfileCoWAccepted=False, guestDaxAccepted=False, crossNodeAccepted=False)
    sets = []
    for guest in config['guests']:
        value = {'sandboxId': guest['sandboxId'], 'pid': guest['pid'], 'processRollup': None,
                 'selectedRam': None}
        output['guests'].append(value)
        try:
            pid = guest['pid']
            if type(pid) is not int or pid <= 1 or type(guest['startTicks']) is not int or ticks(pid) != guest['startTicks']:
                raise ValueError('Exact process identity changed')
            try:
                value['processRollup'] = rollup(pid)
            except (OSError, ValueError) as error:
                value['rollupIssue'] = str(error)[:500]
            ranges = [(int(r['start'], 16), int(r['end'], 16)) for r in guest['ramRanges']]
            if not 1 <= len(ranges) <= 32 or any(a % page or b % page or a >= b for a, b in ranges):
                raise ValueError('Invalid explicit RAM range')
            ordered = sorted(ranges)
            if any(left[1] > right[0] for left, right in zip(ordered, ordered[1:])):
                raise ValueError('Overlapping virtual RAM inputs')
            maps_before = Path(f'/proc/{pid}/maps').read_bytes()
            vm_ranges = [(int(a, 16), int(b, 16)) for a, b in re.findall(rb'^([0-9a-f]+)-([0-9a-f]+)', maps_before, re.M)]
            if any(not any(start <= a and b <= end for start, end in vm_ranges) for a, b in ranges):
                raise ValueError('RAM range not contained in the current VMA inventory')
            first, present, swapped = page_sets(pid, ranges, page)
            filtered, zero, ksm = exclude_non_base(first)
            second, present2, swapped2 = page_sets(pid, ranges, page)
            if (first != second or (present, swapped) != (present2, swapped2)
                    or maps_before != Path(f'/proc/{pid}/maps').read_bytes() or ticks(pid) != guest['startTicks']):
                raise ValueError('Process, mappings or PFNs changed during sample')
            value['selectedRam'] = {'presentVirtualBytes': present * page, 'swappedVirtualBytes': swapped * page,
                                    'zeroExcludedBytes': zero * page, 'ksmExcludedBytes': ksm * page,
                                    'uniquePhysicalBytes': len(filtered) * page}
            sets.append(filtered)
        except (OSError, ValueError) as error:
            value['ramIssue'] = str(error)[:500]
    output['guestRamSharing'] = sharing(sets, page) if len(sets) == len(config['guests']) else None
    for entry in config['files']:
        try:
            output['files'].append(cache_file(entry, page))
        except (OSError, ValueError) as error:
            output['files'].append({'kind': entry.get('kind'), 'sha256': entry.get('sha256'),
                                    'residentBytes': None, 'issue': str(error)[:500]})
    output['finishedNs'] = time.time_ns()
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('config')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    config = read_json(args.config)
    value = collect(config)
    with Path(args.output).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'status': 'SCOPED_SAMPLE_ONLY', 'output': args.output,
                      'completeGuestRamSample': value['guestRamSharing'] is not None,
                      'crossNodeAccepted': False}))


if __name__ == '__main__':
    main()
