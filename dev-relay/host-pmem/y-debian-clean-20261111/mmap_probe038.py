"""Bounded host file-fault probe; never opens an aenv template or changes sysctls.

Production: Linux, jwk UID1002, one deterministic64MiB file,100 forked workers,
three cold/hot pairs. File contents, logical offsets and new worker address spaces
are identical in both conditions. The experiment is separate from lifecycle wall.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import math
import mmap
import multiprocessing
from multiprocessing.connection import wait
import os
from pathlib import Path
import stat
import sys
import time
import traceback


SIZE = 64 * 1024 * 1024
STRIDE = 4096
WORKERS = 100
PAIRS = 3
COLD_MAX_RESIDENT_RATIO = 0.01
HOT_MIN_RESIDENT_RATIO = 0.99
STARTUP_TIMEOUT = 45.0
TOUCH_TIMEOUT = 60.0
GATE_TIMEOUT = STARTUP_TIMEOUT + 30.0


def write_json(path: Path, value: dict) -> None:
    temporary = path.with_name(path.name + '.tmp')
    raw = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    with temporary.open('wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def touch_offsets(size: int, stride: int = STRIDE) -> range:
    if size <= 0 or stride <= 0 or size % stride:
        raise ValueError('size must be positive and exactly divisible by stride')
    return range(0, size, stride)


def expected_checksum(size: int, stride: int = STRIDE) -> int:
    return sum(index % 251 for index, _ in enumerate(touch_offsets(size, stride)))


def cache_state_valid(condition: str, resident_ratio: float) -> bool:
    if not math.isfinite(resident_ratio) or not 0 <= resident_ratio <= 1:
        raise ValueError('invalid residency ratio')
    if condition == 'cold':
        return resident_ratio <= COLD_MAX_RESIDENT_RATIO
    if condition == 'hot':
        return resident_ratio >= HOT_MIN_RESIDENT_RATIO
    raise ValueError('unknown cache condition')


def create_data(path: Path, size: int) -> tuple[int, dict]:
    """Write real, deterministic data rather than a sparse or zero-filled file."""
    touch_offsets(size)
    flags = (os.O_CREAT | os.O_EXCL | os.O_RDWR
             | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
    fd = os.open(path, flags, 0o600)
    digest = hashlib.sha256()
    try:
        chunk_size = min(1024 * 1024, size)
        for start in range(0, size, chunk_size):
            length = min(chunk_size, size - start)
            data = bytearray((bytes(range(256)) * ((length + 255) // 256))[:length])
            for offset in range(0, length, STRIDE):
                data[offset] = ((start + offset) // STRIDE) % 251
            digest.update(data)
            written = 0
            while written < length:
                count = os.write(fd, memoryview(data)[written:])
                if count <= 0:
                    raise OSError('short data-file write')
                written += count
        os.fsync(fd)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size != size:
            raise RuntimeError('unexpected experimental file')
        return fd, {
            'path': str(path), 'bytes': size, 'sha256': digest.hexdigest(),
            'device': info.st_dev, 'inode': info.st_ino,
            'allocatedBytes': getattr(info, 'st_blocks', 0) * 512,
            'generation': 'byte pattern0..255; first byte of logical4KiB page is index modulo251',
        }
    except BaseException:
        os.close(fd)
        raise


def residency(fd: int, size: int) -> dict:
    """mincore on a temporary PROT_READ mapping; never dereference its pages."""
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                          ctypes.c_int, ctypes.c_int, ctypes.c_longlong]
    libc.mmap.restype = ctypes.c_void_p
    libc.mincore.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
    libc.mincore.restype = ctypes.c_int
    libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    libc.munmap.restype = ctypes.c_int
    address = libc.mmap(None, size, mmap.PROT_READ, mmap.MAP_PRIVATE, fd, 0)
    if address == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_errno(), 'experimental file mmap for mincore failed')
    try:
        page_size = os.sysconf('SC_PAGE_SIZE')
        pages = (size + page_size - 1) // page_size
        vector = ctypes.create_string_buffer(pages)
        if libc.mincore(address, size, vector) != 0:
            raise OSError(ctypes.get_errno(), 'mincore failed')
        resident = sum(value & 1 for value in vector.raw)
        return {
            'method': 'temporary readonly MAP_PRIVATE mincore; no page touching',
            'systemPageSize': page_size, 'pages': pages, 'residentPages': resident,
            'residentRatio': resident / pages,
        }
    finally:
        if libc.munmap(address, size) != 0:
            raise OSError(ctypes.get_errno(), 'mincore mapping unmap failed')


def process_memory() -> dict:
    """Ready-state interpreter overhead, separate from the shared data working set."""
    result = {}
    try:
        for line in Path('/proc/self/smaps_rollup').read_text().splitlines():
            fields = line.split()
            if fields and fields[0] in (
                'Rss:', 'Pss:', 'Private_Clean:', 'Private_Dirty:',
                'Shared_Clean:', 'Shared_Dirty:',
            ):
                result[fields[0].rstrip(':') + 'KiB'] = int(fields[1])
    except OSError as error:
        result['unavailable'] = type(error).__name__
    return result


def usage_delta(before, after) -> dict:
    return {
        'userCpuSeconds': after.ru_utime - before.ru_utime,
        'systemCpuSeconds': after.ru_stime - before.ru_stime,
        'minorFaults': after.ru_minflt - before.ru_minflt,
        'majorFaults': after.ru_majflt - before.ru_majflt,
        'voluntarySwitches': after.ru_nvcsw - before.ru_nvcsw,
        'involuntarySwitches': after.ru_nivcsw - before.ru_nivcsw,
    }


def touch_worker(index: int, path: str, size: int, identity: tuple[int, int],
                 gate, connection) -> None:
    import resource

    fd = None
    mapping = None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        info = os.fstat(fd)
        if ((info.st_dev, info.st_ino) != identity or info.st_size != size
                or not stat.S_ISREG(info.st_mode)):
            raise RuntimeError('experimental file identity changed')
        mapping = mmap.mmap(fd, size, flags=mmap.MAP_PRIVATE, prot=mmap.PROT_READ)
        connection.send({'kind': 'ready', 'worker': index, 'pid': os.getpid(),
                         'readyMonotonicNs': time.monotonic_ns(),
                         'memoryBeforeTouch': process_memory()})
        if not gate.wait(GATE_TIMEOUT):
            raise TimeoutError('worker start gate deadline')
        before = resource.getrusage(resource.RUSAGE_SELF)
        start = time.monotonic_ns()
        checksum = 0
        for offset in touch_offsets(size):
            checksum += mapping[offset]
        end = time.monotonic_ns()
        after = resource.getrusage(resource.RUSAGE_SELF)
        connection.send({
            'kind': 'result', 'worker': index, 'pid': os.getpid(),
            'startMonotonicNs': start, 'endMonotonicNs': end,
            'elapsedSeconds': (end - start) / 1e9,
            'logicalTouches': len(touch_offsets(size)), 'checksum': checksum,
            'maxRssKiB': after.ru_maxrss,
            **usage_delta(before, after),
        })
    except BaseException as error:
        try:
            connection.send({'kind': 'error', 'worker': index, 'pid': os.getpid(),
                             'errorType': type(error).__name__,
                             'error': str(error)[:1000]})
        except (OSError, EOFError, BrokenPipeError):
            pass
    finally:
        if mapping is not None:
            mapping.close()
        if fd is not None:
            os.close(fd)
        connection.close()


def reap_workers(processes) -> dict:
    """Bounded normal exit, SIGTERM, then SIGKILL; only our Process objects."""
    deadline = time.monotonic() + 3
    for process in processes:
        process.join(max(0, deadline - time.monotonic()))
    terminated = []
    killed = []
    for process in processes:
        if process.is_alive():
            process.terminate()
            terminated.append(process.pid)
    deadline = time.monotonic() + 4
    for process in processes:
        process.join(max(0, deadline - time.monotonic()))
    for process in processes:
        if process.is_alive():
            process.kill()
            killed.append(process.pid)
    deadline = time.monotonic() + 4
    for process in processes:
        process.join(max(0, deadline - time.monotonic()))
    alive = [process.pid for process in processes if process.is_alive()]
    exits = {str(process.pid): process.exitcode for process in processes}
    for process in processes:
        if not process.is_alive():
            process.close()
    return {'terminatedPids': terminated, 'killedPids': killed,
            'remainingPids': alive, 'exitCodes': exits}


def receive_all(connections, kind: str, deadline: float) -> list[dict]:
    pending = dict(connections)
    messages = []
    while pending:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f'{kind} deadline; missing workers {list(pending.values())}')
        ready = wait(list(pending), timeout=min(remaining, 0.5))
        for connection in ready:
            worker = pending.pop(connection)
            try:
                message = connection.recv()
            except EOFError as error:
                raise RuntimeError(f'worker {worker} exited before {kind}') from error
            if message.get('worker') != worker or message.get('kind') != kind:
                raise RuntimeError(f'worker {worker} unexpected message: {message}')
            messages.append(message)
    return sorted(messages, key=lambda item: item['worker'])


def run_case(fd: int, data: dict, size: int, workers: int,
             pair: int, condition: str) -> dict:
    result = {'pair': pair, 'condition': condition, 'success': False,
              'workersRequested': workers}
    processes = []
    connections = {}
    preparation_start = time.monotonic_ns()
    try:
        if condition == 'cold':
            os.fsync(fd)
            os.posix_fadvise(fd, 0, size, os.POSIX_FADV_DONTNEED)
            result['preparation'] = 'fsync + POSIX_FADV_DONTNEED on this experimental file only; hint, not guaranteed eviction'
        elif condition == 'hot':
            with mmap.mmap(fd, size, flags=mmap.MAP_PRIVATE,
                           prot=mmap.PROT_READ) as mapping:
                checksum = sum(mapping[offset] for offset in touch_offsets(size))
            if checksum != expected_checksum(size):
                raise RuntimeError('parent prewarm checksum mismatch')
            result['preparation'] = 'parent readonly touch of the fixed offset sequence; mapping closed before workers start'
        else:
            raise ValueError('unknown cache condition')
        result['residencyAfterPreparation'] = residency(fd, size)
        context = multiprocessing.get_context('fork')
        gate = context.Event()
        startup_deadline = time.monotonic() + STARTUP_TIMEOUT
        for index in range(workers):
            parent_connection, child_connection = context.Pipe(duplex=False)
            process = context.Process(
                target=touch_worker,
                args=(index, data['path'], size,
                      (data['device'], data['inode']), gate, child_connection),
                name=f'mmap-probe-{index}',
            )
            try:
                process.start()
            except BaseException:
                parent_connection.close()
                child_connection.close()
                raise
            child_connection.close()
            processes.append(process)
            connections[parent_connection] = index
        ready = receive_all(connections, 'ready', startup_deadline)
        result['ready'] = ready
        result['residencyBeforeGate'] = residency(fd, size)
        ratio = result['residencyBeforeGate']['residentRatio']
        result['cacheStateVerified'] = cache_state_valid(condition, ratio)
        result['validCold'] = result['cacheStateVerified'] if condition == 'cold' else None
        result['validHot'] = result['cacheStateVerified'] if condition == 'hot' else None
        release = time.monotonic_ns()
        result['gateReleaseMonotonicNs'] = release
        result['preparationAndWorkerStartupSeconds'] = (release - preparation_start) / 1e9
        gate.set()
        measured = receive_all(connections, 'result', time.monotonic() + TOUCH_TIMEOUT)
        checksum = expected_checksum(size)
        if any(row['checksum'] != checksum for row in measured):
            raise RuntimeError('worker checksum mismatch')
        result['workers'] = measured
        result['touchWallSeconds'] = (max(row['endMonotonicNs'] for row in measured) - release) / 1e9
        result['firstWorkerStartDelaySeconds'] = (min(row['startMonotonicNs'] for row in measured) - release) / 1e9
        result['lastWorkerStartDelaySeconds'] = (max(row['startMonotonicNs'] for row in measured) - release) / 1e9
        result['workerStartSpreadSeconds'] = (
            max(row['startMonotonicNs'] for row in measured)
            - min(row['startMonotonicNs'] for row in measured)) / 1e9
        result['sumUserCpuSeconds'] = sum(row['userCpuSeconds'] for row in measured)
        result['sumSystemCpuSeconds'] = sum(row['systemCpuSeconds'] for row in measured)
        result['minorFaults'] = sum(row['minorFaults'] for row in measured)
        result['majorFaults'] = sum(row['majorFaults'] for row in measured)
        result['logicalTouchesPerWorker'] = len(touch_offsets(size))
        result['residencyAfterTouch'] = residency(fd, size)
        result['success'] = True
    except BaseException as error:
        result.update(errorType=type(error).__name__, error=str(error)[:2000])
    finally:
        result['cleanup'] = reap_workers(processes)
        for connection in connections:
            connection.close()
        if (result['cleanup']['remainingPids'] or result['cleanup']['terminatedPids']
                or result['cleanup']['killedPids']
                or any(code != 0 for code in result['cleanup']['exitCodes'].values())):
            result['success'] = False
    return result


def run(output: Path, self_test: bool = False) -> dict:
    if not sys.platform.startswith('linux'):
        raise RuntimeError('this probe requires Linux mmap/mincore/fadvise/fork')
    if not self_test and (os.getuid() != 1002 or os.geteuid() != 1002):
        raise PermissionError('production probe must run as jwk UID1002')
    output = output.absolute()
    if output.parent.resolve() != output.parent:
        raise RuntimeError('redirected output parent preserved')
    output.mkdir(mode=0o700, exist_ok=False)
    size, workers, pairs = ((1024 * 1024, 4, 1) if self_test else (SIZE, WORKERS, PAIRS))
    result = {
        'experiment': 'host-file-mmap-cold-hot', 'selfTest': self_test,
        'success': False, 'executionSuccess': False, 'validComparison': False,
        'fileBytes': size, 'workersPerCase': workers, 'pairsRequested': pairs,
        'logicalStrideBytes': STRIDE, 'systemPageSize': os.sysconf('SC_PAGE_SIZE'),
        'logicalTouchesPerWorker': len(touch_offsets(size)),
        'coldMaxResidentRatio': COLD_MAX_RESIDENT_RATIO,
        'hotMinResidentRatio': HOT_MIN_RESIDENT_RATIO,
        'cases': [],
        'timingDefinition': 'Group wall: immediately before gate.set to last worker touch completion; includes gate wakeup/scheduling, excludes file preparation, process creation, open/mmap, ready handshake, mincore and result collection. Per-worker CPU/fault deltas surround only the timed readonly Python byte-access loop and timestamps.',
        'resourceDefinition': 'One shared file working set; forked Python workers also have interpreter, COW-private memory and page-table overhead. RSS values include shared pages and must not be summed as unique physical memory.',
        'interpretation': 'Host mmap/file-fault isolation only, without KVM or Guest execution. Python loop and scheduling overhead remain. A Y-only result cannot establish an X/Y kernel root cause. fadvise is a hint; invalid cold/hot states remain in output and are never retried or selected away.',
        'cacheThresholdPolicy': 'Residency checked again after all workers are ready, before releasing the gate; no page touching by mincore.',
    }
    fd = None
    data = None
    path = output / 'probe-data.bin'
    try:
        fd, data = create_data(path, size)
        result['data'] = data
        for pair in range(1, pairs + 1):
            for condition in ('cold', 'hot'):
                case = run_case(fd, data, size, workers, pair, condition)
                result['cases'].append(case)
                write_json(output / f'pair{pair}-{condition}.json', case)
                write_json(output / 'result.json', result)
                if not case['success']:
                    raise RuntimeError(f'worker execution failed at pair{pair}/{condition}')
        result['executionSuccess'] = True
        result['coldStateVerified'] = all(c['validCold'] for c in result['cases'] if c['condition'] == 'cold')
        result['hotStateVerified'] = all(c['validHot'] for c in result['cases'] if c['condition'] == 'hot')
        result['validComparison'] = result['coldStateVerified'] and result['hotStateVerified']
        result['success'] = result['executionSuccess'] and result['validComparison']
    except BaseException as error:
        result.update(errorType=type(error).__name__, error=str(error)[:2000])
    finally:
        if fd is not None:
            os.close(fd)
        try:
            if data is not None and path.exists():
                info = path.lstat()
                if ((info.st_dev, info.st_ino) != (data['device'], data['inode'])
                        or not stat.S_ISREG(info.st_mode)):
                    raise RuntimeError('experimental file changed; preserved')
                if any(case.get('cleanup', {}).get('remainingPids') for case in result['cases']):
                    raise RuntimeError('worker still alive; experimental file retained')
                path.unlink()
            result['experimentalFileRemoved'] = not path.exists()
        except BaseException as error:
            result.update(success=False, executionSuccess=False,
                          fileCleanupError=type(error).__name__ + ': ' + str(error)[:1000])
        write_json(output / 'result.json', result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--self-test', action='store_true',
                        help='Linux-only small fixture:1MiB/4workers/1pair')
    args = parser.parse_args()
    try:
        result = run(args.output, args.self_test)
    except BaseException as error:
        print(json.dumps({'executionSuccess': False, 'success': False,
                          'errorType': type(error).__name__, 'error': str(error)[:1500]}), flush=True)
        return 1
    print(json.dumps({
        'executionSuccess': result['executionSuccess'], 'success': result['success'],
        'validComparison': result['validComparison'],
        'coldStateVerified': result.get('coldStateVerified'),
        'hotStateVerified': result.get('hotStateVerified'),
        'casesCompleted': len(result['cases']),
        'experimentalFileRemoved': result.get('experimentalFileRemoved'),
        'caseSummary': [{k: row.get(k) for k in (
            'pair', 'condition', 'success', 'validCold', 'validHot',
            'touchWallSeconds', 'sumUserCpuSeconds', 'sumSystemCpuSeconds',
            'minorFaults', 'majorFaults')} for row in result['cases']],
    }, separators=(',', ':')), flush=True)
    # An unverified cache state is data, not permission to claim a cold/hot result.
    # Exit0 permits evidence return; inspect success/validComparison separately.
    return 0 if result['executionSuccess'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
