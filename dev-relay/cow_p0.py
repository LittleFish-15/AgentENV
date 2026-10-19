"""P0: existing experimental services, sample inventory and measurement capability.

Ordinary jwk only. No Guest/UB allocation, downloads, service start or repair.
Run after closing the previous SSH session and reconnecting: cow_p0.py node-a|node-b
"""
import argparse
import ctypes
import hashlib
import http.client
import json
import mmap
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path('/home/jwk/agent')
REVISION = 'cow-p0-v1'
LIMIT = 1024 * 1024
METRICS = {'Size', 'Rss', 'Pss', 'Pss_Dirty', 'Shared_Clean', 'Shared_Dirty',
           'Private_Clean', 'Private_Dirty', 'Anonymous', 'Swap', 'SwapPss',
           'AnonHugePages', 'Shared_Hugetlb', 'Private_Hugetlb'}


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def failure(error):
    # Exception bodies from HTTP and subprocess output are deliberately withheld.
    result = {'available': False, 'error_type': type(error).__name__,
              'errno': getattr(error, 'errno', None)}
    if type(error) is RuntimeError:
        result['reason'] = str(error)[:400]
    return result


def safe(path):
    path = Path(path)
    require(path.is_absolute() and path.is_relative_to(ROOT) and path.resolve() == path,
            'Path outside workspace or redirected')
    return path


def read_file(path, limit=LIMIT):
    path = safe(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        meta = os.fstat(stream.fileno())
        require(stat.S_ISREG(meta.st_mode) and meta.st_uid == 1204,
                'Unexpected file type or owner')
        require(meta.st_size <= limit, 'Input exceeds read limit')
        data = stream.read(limit + 1)
        require(len(data) <= limit, 'Input grew beyond read limit')
        return data


def file_meta(path):
    try:
        path = safe(path)
        m = path.lstat()
        require(stat.S_ISREG(m.st_mode) and m.st_uid == 1204, 'Unexpected layer file')
        return {'available': True, 'path': str(path), 'dev': m.st_dev, 'inode': m.st_ino,
                'stored_file_bytes': m.st_size, 'allocated_file_bytes': m.st_blocks * 512,
                'mtime_ns': m.st_mtime_ns, 'nlink': m.st_nlink,
                'content_hash_read': False, 'exclusive_disk_bytes_verified': False}
    except Exception as error:
        return dict(failure(error), path=str(path))


def parse_smaps(text):
    """Aggregate only; no claim these whole-process metrics are Guest RAM."""
    sums, vmas, page_sizes = {}, 0, set()
    for line in text.splitlines():
        if re.match(r'^[0-9a-f]+-[0-9a-f]+\s', line):
            vmas += 1
        match = re.fullmatch(r'([A-Za-z_]+):\s+(\d+) kB', line)
        if not match:
            continue
        name, value = match[1], int(match[2]) * 1024
        if name in METRICS:
            sums[name] = sums.get(name, 0) + value
        if name in ('KernelPageSize', 'MMUPageSize'):
            page_sizes.add(value)
    return {'scope': 'whole_process_not_guest_ram', 'vma_count': vmas,
            'bytes': sums, 'reported_page_sizes_bytes': sorted(page_sizes)}


def process_sample(pid, expected_ticks=None):
    try:
        require(isinstance(pid, int) and pid > 1, 'Invalid PID')
        proc = Path('/proc') / str(pid)
        before = (proc / 'stat').read_text().rsplit(')', 1)[1].split()[19]
        if expected_ticks is not None:
            require(before == expected_ticks, 'PID was reused')
        status = (proc / 'status').read_text()
        uid = re.search(r'^Uid:\s+(.+)$', status, re.M)
        require(uid and [int(x) for x in uid[1].split()] == [1204] * 4, 'Unexpected process UID')
        result = {'pid': pid, 'start_ticks': before}
        try:
            with (proc / 'smaps').open() as f:
                data = f.read(16 * LIMIT + 1)
            require(len(data) <= 16 * LIMIT, 'smaps exceeds limit')
            result['smaps'] = dict(available=True, **parse_smaps(data))
        except Exception as error:
            result['smaps'] = failure(error)
        require((proc / 'stat').read_text().rsplit(')', 1)[1].split()[19] == before,
                'Process changed while sampling')
        return result
    except Exception as error:
        return dict(failure(error), pid=pid)


def api_inventory(base, port, endpoint, fields):
    """Only fixed read-only routes. Never persist credentials or arbitrary bodies."""
    require((port, endpoint) in {(p, e) for p in (18080, 18081)
                               for e in ('/v2/templates', '/snapshots?limit=100')},
            'Unexpected API target')
    key = read_file(base / 'config/api-key', 1024).decode().strip()
    require(re.fullmatch(r'e2b_[A-Za-z0-9._~-]+', key), 'Unexpected API credential format')
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
    try:
        conn.request('GET', endpoint, headers={'X-API-Key': key})
        response = conn.getresponse()
        require(response.status == 200, 'Metadata endpoint HTTP ' + str(response.status))
        raw = response.read(LIMIT + 1)
        require(len(raw) <= LIMIT, 'Metadata response exceeds limit')
        rows = json.loads(raw)
        require(isinstance(rows, list) and len(rows) <= 1000, 'Unexpected metadata list')
        # Exclude envVars, access tokens, image URLs, commands, user metadata and names.
        selected = []
        for row in rows:
            require(isinstance(row, dict), 'Unexpected metadata row')
            selected.append({k: row[k] for k in fields if k in row
                             and isinstance(row[k], (str, int, bool, type(None)))})
        return {'available': True, 'items': selected,
                'complete': not bool(response.getheader('x-next-token')),
                'route': endpoint, 'raw_response_saved': False}
    finally:
        conn.close()


def catalog_projection(path, record):
    committed = record.get('committed') or {}
    result = {'path': str(path), 'snapshot_id': record.get('id'), 'layers': [],
              'committed': bool(committed), 'content_hashes_verified': False}
    for kind in ('memory', 'rootfs'):
        layers = committed.get(kind + '_layers', [])
        require(isinstance(layers, list) and len(layers) <= 256, 'Invalid committed layers')
        for layer in layers:
            origin = 'Managed' if kind == 'memory' else next(iter(layer), '')
            value = layer if kind == 'memory' else layer.get(origin, {})
            digest, size = value.get('digest'), value.get('size')
            require(isinstance(digest, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', digest), 'Unexpected declared layer digest')
            require(isinstance(size, int) and size >= 0, 'Unexpected declared layer size')
            row = {'kind': kind, 'origin': origin, 'digest': digest, 'stored_bytes_declared': size}
            if origin == 'Managed':
                repo = path.parent.parent.parent  # repository/catalog/records/id.json
                row['local_file'] = file_meta(repo / 'managed-layers' / (digest.replace(':', '_') + '.overlaybd.commit'))
            else:
                row['local_file'] = {'available': False, 'reason': 'EXTERNAL_LAYER_PLACEMENT_NOT_RESOLVED_NO_DOWNLOAD'}
            result['layers'].append(row)
    return result


def io_config_inventory(base):
    result = {}
    for name in ('overlaybd-global.json', 'mem-overlaybd-global.json', 'resize-overlaybd-global.json'):
        try:
            cfg = json.loads(read_file(base / 'state/overlaybd' / name))
            row = {k: cfg[k] for k in ('ioEngine', 'enableThread', 'registryCacheSizeGB')
                   if k in cfg and isinstance(cfg[k], (int, bool))}
            cache_type = cfg.get('cacheType')
            row['cacheType'] = cache_type if cache_type in ('file', 'ocf', '') else 'UNRECOGNIZED_OR_ABSENT'
            row['configured_only_actual_fd_flags_not_verified'] = True
            result[name] = row
        except Exception as error:
            result[name] = failure(error)
    return result


def layer_inventory(base):
    """Bounded enumeration in this deployment's state only; never reads layer bytes."""
    state = safe(base / 'state')
    result = {'configs': [], 'committed_records': [], 'entries_scanned': 0, 'complete': True, 'errors': []}
    if not state.is_dir():
        return dict(result, complete=False, reason='STATE_DIRECTORY_MISSING')
    todo = [(state, 0)]
    while todo:
        directory, depth = todo.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    result['entries_scanned'] += 1
                    if result['entries_scanned'] > 12000 or len(result['configs']) + len(result['committed_records']) >= 128:
                        result['complete'] = False
                        return result
                    if entry.is_symlink():
                        continue
                    path = Path(entry.path)
                    if entry.is_dir(follow_symlinks=False):
                        if depth < 9:
                            todo.append((safe(path), depth + 1))
                        else:
                            result['complete'] = False
                        continue
                    catalog = path.parent.name == 'records' and path.parent.parent.name == 'catalog' and path.suffix == '.json'
                    if not catalog and entry.name != 'image.json' and not (entry.name.startswith('.ub-view-') and entry.name.endswith('.json')):
                        continue
                    try:
                        cfg = json.loads(read_file(path))
                        if catalog:
                            result['committed_records'].append(catalog_projection(path, cfg))
                            continue
                        if not isinstance(cfg, dict) or not isinstance(cfg.get('lowers'), list):
                            continue
                        require(len(cfg['lowers']) <= 256, 'Too many lowers')
                        item = {'path': str(path), 'kind': 'UNCLASSIFIED_UNTIL_SNAPSHOT_BINDING', 'lowers': []}
                        for lower in cfg['lowers']:
                            require(isinstance(lower, dict), 'Invalid lower')
                            digest = lower.get('digest')
                            size = lower.get('size')
                            row = {'declared_digest': digest if isinstance(digest, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', digest) else None,
                                   'declared_size': size if isinstance(size, int) and size >= 0 else None, 'digest_verified': False,
                                   'ub_configured': lower.get('ub') is not None}
                            candidates = []
                            if isinstance(lower.get('file'), str) and lower['file']:
                                candidates = [Path(lower['file'])]
                            elif isinstance(lower.get('dir'), str) and lower['dir']:
                                candidates = [Path(lower['dir']) / name for name in ('overlaybd.commit', 'overlaybd.sealed')]
                            row['local_candidates'] = [file_meta(p if p.is_absolute() else path.parent / p)
                                                       for p in candidates]
                            item['lowers'].append(row)
                        upper = cfg.get('upper') or {}
                        item['upper'] = {k: file_meta(Path(v) if Path(v).is_absolute() else path.parent / v)
                                         for k, v in upper.items() if k in ('data', 'index', 'target') and isinstance(v, str) and v}
                        result['configs'].append(item)
                    except Exception as error:
                        result['errors'].append(dict(failure(error), path=str(path)))
                        result['complete'] = False
        except Exception as error:
            result['errors'].append(dict(failure(error), path=str(directory)))
            result['complete'] = False
    return result


def measurement_probe(work):
    """Four-page disposable file only. This is not a measurement of actual layers."""
    page = os.sysconf('SC_PAGESIZE')
    path = work / 'cache-capability-probe.bin'
    result = {'page_size_bytes': page, 'scope': 'own_test_file_only_not_actual_layers',
              'cachestat': {'available': False, 'reason': 'NOT_PROBED_NO_GUESSED_SYSCALL_NUMBER'},
              'target_pfn_visibility': 'NOT_TESTED_NO_GUEST_CREATED'}
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mmap.restype = ctypes.c_void_p
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
    libc.mincore.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
    libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    address = None
    try:
        with path.open('xb') as f:
            f.truncate(page * 4)
            f.write(b'P0-measurement-probe')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            address = libc.mmap(None, page * 4, 1, 1, fd, 0)  # PROT_READ, MAP_SHARED; no touch
        finally:
            os.close(fd)
        require(address not in (None, ctypes.c_void_p(-1).value), 'Probe mmap failed')
        bits = (ctypes.c_ubyte * 4)()
        if libc.mincore(address, page * 4, bits) != 0:
            raise OSError(ctypes.get_errno(), 'mincore')
        result['mincore'] = {'available': True, 'resident_bitmap': [bool(x & 1) for x in bits],
                             'file_owner_is_current_user': True, 'mapping_touched_by_sampler': False,
                             'arbitrary_file_or_device_support_proven': False}
    except Exception as error:
        result['mincore'] = failure(error)
    finally:
        if address not in (None, ctypes.c_void_p(-1).value):
            result['unmap_rc'] = libc.munmap(address, page * 4)
        if path.exists():
            path.unlink()
        result['probe_file_removed'] = not path.exists()
    # A deliberately touched private self page tests PFN masking, not Guest sharing.
    try:
        with mmap.mmap(-1, page) as anon:
            anon[0] = 77
            cell = ctypes.c_char.from_buffer(anon)
            at = ctypes.addressof(cell)
            del cell
            with open('/proc/self/pagemap', 'rb', buffering=0) as f:
                f.seek((at // page) * 8)
                entry = struct.unpack('Q', f.read(8))[0]
            result['self_pagemap'] = {'readable': True, 'present': bool(entry >> 63),
                                      'pfn_nonzero': bool(entry & ((1 << 55) - 1)),
                                      'raw_pfn_saved': False}
    except Exception as error:
        result['self_pagemap'] = failure(error)
    return result


def service_health(node, work):
    base = ROOT / 'deployments/agentenv-ub-b019f27'
    launcher = safe(base / ('libexec/deploy_a_ub.py' if node == 'node-a' else 'libexec/deploy_b_ub.py'))
    receipt = json.loads(read_file(base / 'installation.json', 65536))
    require(receipt.get('node') == node and receipt.get('launcher') == str(launcher), 'Installation identity differs')
    require(hashlib.sha256(read_file(launcher)).hexdigest() == receipt['launcher_sha256'], 'Launcher hash differs')
    for name, digest in receipt.get('launcher_dependencies', {}).items():
        require(Path(name).name == name, 'Invalid launcher dependency')
        require(hashlib.sha256(read_file(launcher.parent / name)).hexdigest() == digest, 'Launcher dependency differs')
    # Always post-disconnect: never start a missing proxy to mask its failure.
    with (work / 'health-output.txt').open('wb') as output:
        run = subprocess.run(['/usr/bin/python3', '-I', '-B', str(launcher), 'health', '--post-disconnect'],
                             stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, timeout=240)
    raw = read_file(work / 'health-output.txt')
    try:
        report = json.loads(raw.decode().split('BEGIN_RETURN_REPORT', 1)[1].split('END_RETURN_REPORT', 1)[0])
    except Exception:
        raise RuntimeError('Health returned no parseable report; own bounded output retained') from None
    expected = ('A' if node == 'node-a' else 'B') + '_UB_AND_ORIGINAL_SERVICES_HEALTHY'
    return {'verified': run.returncode == 0 and report.get('status') == expected and report.get('post_disconnect') is True,
            'exit_code': run.returncode, 'report': report}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('node', choices=('node-a', 'node-b'))
    args = parser.parse_args()
    require(sys.platform == 'linux' and os.uname().machine == 'aarch64', 'Expected Linux ARM64')
    require(socket.gethostname() == {'node-a': 'server1', 'node-b': 'agent1'}[args.node], 'Unexpected hostname')
    require(os.getuid() == os.geteuid() == 1204 and os.getgid() == os.getegid() == 1205, 'Ordinary jwk only')
    status = Path('/proc/self/status').read_text()
    require(all(int(v, 16) == 0 for k, v in re.findall(r'^(Cap(?:Inh|Prm|Eff|Amb)):\s*(\w+)$', status, re.M)), 'Collector must have no capabilities')
    os.umask(0o077)
    reports = safe(ROOT / 'relay/reports')
    work = Path(tempfile.mkdtemp(prefix=args.node + '-cow-p0-', dir=reports))
    report = {'revision': REVISION, 'node': args.node, 'hostname': socket.gethostname(),
              'uid': os.getuid(), 'report_directory': str(work),
              'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
              'kernel_release': os.uname().release,
              'collector_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'SDK_called': False, 'Guest_created': False, 'service_mutations': False,
              'full_cow_experiment_executed': False, 'started_unix': time.time()}
    try:
        print('PHASE=post_disconnect_health', flush=True)
        report['health'] = service_health(args.node, work)
        require(report['health']['verified'], 'Post-disconnect health failed; included report has details')
        report['capacity'] = {'free_workspace_bytes': os.statvfs(ROOT).f_bavail * os.statvfs(ROOT).f_frsize,
                              'page_size_bytes': os.sysconf('SC_PAGESIZE')}
        report['capacity']['meminfo_kib'] = {k: int(v) for k, v in re.findall(
            r'^(MemTotal|MemAvailable|SwapTotal|SwapFree):\s+(\d+) kB$', Path('/proc/meminfo').read_text(), re.M)}
        report['measurement_probe'] = measurement_probe(work)
        report['profiles'] = {}
        for profile, suffix, port in [('original', 'agentenv-ae9c626-baseline', 18080),
                                       ('modified', 'agentenv-ub-b019f27', 18081)]:
            print('PHASE=inventory_' + profile, flush=True)
            base = ROOT / 'deployments' / suffix
            row = {}
            for name, endpoint, fields in [('templates', '/v2/templates', ('templateID', 'buildID', 'buildStatus', 'cpuCount', 'memoryMB', 'diskSizeMB')),
                                           ('snapshots', '/snapshots?limit=100', ('snapshotID',))]:
                try:
                    row[name] = api_inventory(base, port, endpoint, fields)
                except Exception as error:
                    row[name] = failure(error)
            row['layers'] = layer_inventory(base)
            row['io_configuration'] = io_config_inventory(base)
            unit = 'jwk-aenv-' + ('ae9c626-' if profile == 'original' else 'ub-b019f27-') + args.node + '.service'
            try:
                r = subprocess.run(['/usr/bin/systemctl', 'show', unit, '--property=MainPID', '--value'],
                                   capture_output=True, text=True, timeout=10, check=True)
                row['runtime_memory_access'] = process_sample(int(r.stdout.strip()))
            except Exception as error:
                row['runtime_memory_access'] = failure(error)
            report['profiles'][profile] = row
        original = report['profiles']['original']
        report['sample_selection'] = {'automatic_guest_start': False,
            'ready_template_ids': [r['templateID'] for r in original['templates'].get('items', [])
                                   if r.get('buildStatus') == 'ready' and 'templateID' in r],
            'snapshot_ids_first_page': [r['snapshotID'] for r in original['snapshots'].get('items', []) if 'snapshotID' in r],
            'compatibility_and_full_closure_verified': False,
            'tools_ext4_is_not_a_bootable_experiment_template': True}
        report['status'] = 'P0_COLLECTED_REVIEW_CAPABILITIES_AND_SAMPLE_INPUTS'
        report['next_action'] = 'RETURN_BOTH_NODE_REPORTS_FOR_P1_SAMPLE_AND_COLLECTOR_BINDING'
    except Exception as error:
        report['status'] = 'STOPPED_COW_P0'
        report['error'] = failure(error)
        report['next_action'] = 'RETURN_REPORT_PRESERVE_EXISTING_SERVICES_AND_FILES'
    report['finished_unix'] = time.time()
    (work / 'return.json').write_text(json.dumps(report, indent=2) + '\n')
    print('BEGIN_RETURN_REPORT')
    print(json.dumps(report, indent=2))
    print('END_RETURN_REPORT')
    return 0 if report['status'].startswith('P0_COLLECTED') else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print('BEGIN_RETURN_REPORT')
        print(json.dumps({'status': 'STOPPED_COW_P0_ENTRY', 'error': failure(error)}))
        print('END_RETURN_REPORT')
        raise SystemExit(1)
