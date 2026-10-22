"""Scoped Runtime API and read-only metrics for the native four cohort."""

import argparse

import concurrent.futures

import hashlib

import http.client

import importlib.util

import json

import os

from pathlib import Path

import re

import signal

import socket

import stat

import subprocess

import sys

import time

import uuid

def need(ok, reason):
    if not ok:
        raise RuntimeError(reason)

def read(path, limit=2 * 1024**2):
    path = Path(path)
    need(path.is_absolute() and path.is_relative_to(ROOT) and path.resolve(strict=True) == path,
         'Input outside workspace or redirected')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 1204 and before.st_size <= limit,
             'Input ownership, type or size differs')
        value = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    need(len(value) == before.st_size and (before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
         (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'Input changed while reading')
    return value

def load(path):
    return json.loads(read(path))

def save(path, value):
    need(path.parent.resolve(strict=True) == path.parent and path.parent.stat().st_uid == 1204,
         'Output directory changed')
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    with temporary.open('xb') as stream:
        stream.write((json.dumps(value, indent=2) + '\n').encode())
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def digest_file(path, limit=512 * 1024**2):
    path = Path(path)
    need(path.resolve(strict=True) == path and path.is_relative_to(ROOT), 'Binary path changed')
    with path.open('rb') as stream:
        meta = os.fstat(stream.fileno())
        need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 1204 and 0 < meta.st_size <= limit,
             'Binary metadata differs')
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        end = os.fstat(stream.fileno())
    need((meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns) ==
         (end.st_size, end.st_mtime_ns, end.st_ctime_ns), 'Binary changed')
    return digest

def unit_fields(unit):
    result = subprocess.run(['/usr/bin/systemctl', 'show', unit,
                             '--property=LoadState,ActiveState,MainPID,User,Group,ControlGroup'],
                            capture_output=True, text=True, timeout=10, check=True)
    return dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)

def ticks(pid):
    return Path('/proc/' + str(pid) + '/stat').read_text().rsplit(')', 1)[1].split()[19]

class Api:
    def __init__(self, base, unit, port):
        self.base, self.unit, self.port = base, unit, port
        self.key = read(base / 'config/api-key', 1024).decode().strip()
        need(re.fullmatch(r'e2b_[A-Za-z0-9._~-]+', self.key), 'Credential format differs; value withheld')
        fields = unit_fields(unit)
        need(fields.get('ActiveState') == 'active' and fields.get('User') == fields.get('Group') == 'jwk',
             'Declared Runtime is not active under the expected user')
        self.pid = int(fields['MainPID'])
        need(self.pid > 1, 'Invalid Runtime PID')
        self.ticks = ticks(self.pid)
        self.cgroup = fields['ControlGroup']
        self.config_sha = hashlib.sha256(read(base / 'config/runtime.toml')).hexdigest()

    def stable(self):
        need(int(unit_fields(self.unit)['MainPID']) == self.pid and ticks(self.pid) == self.ticks
             and hashlib.sha256(read(self.base / 'config/runtime.toml')).hexdigest() == self.config_sha,
             'Runtime/config changed; no further API request')

    def call(self, method, path, body=None, timeout=30):
        self.stable()
        allowed = path in ('/health', '/sandboxes-cold', '/v2/sandboxes', '/v2/sandboxes?limit=1')
        allowed = allowed or re.fullmatch(r'/sandboxes/[A-Za-z0-9_-]{1,128}(?:/snapshots|/fork)?', path)
        allowed = allowed or (method in ('GET', 'DELETE') and re.fullmatch(r'/templates/[0-9a-f-]{36}', path))
        need(allowed and method in ('GET', 'POST', 'DELETE'), 'Route outside cohort scope')
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=timeout)
        try:
            connection.request(method, path, json.dumps(body).encode() if body is not None else None,
                               {'Content-Type': 'application/json', 'X-API-Key': self.key})
            response = connection.getresponse()
            raw = response.read(2 * 1024**2 + 1)
            need(len(raw) <= 2 * 1024**2 and not response.getheader('X-Next-Token'),
                 'Oversized or paginated reply; inventory uncertain')
            return response.status, json.loads(raw) if raw else None
        finally:
            connection.close()

def cgroup_memory(group, scope='runtime_unit_charge_including_retained_pools_and_helpers'):
    try:
        need(isinstance(group, str) and group.startswith('/') and '..' not in group.split('/'), 'Invalid cgroup')
        directory = Path('/sys/fs/cgroup' + group)
        need(directory.resolve(strict=True) == directory, 'Redirected cgroup')
        current = int((directory / 'memory.current').read_text())
        fields = dict(line.split() for line in (directory / 'memory.stat').read_text().splitlines())
        return {'available': True, 'currentBytes': current,
                'statBytes': {k: int(fields[k]) for k in ('anon', 'file', 'kernel', 'shmem', 'slab') if k in fields},
                'scope': scope, 'UBPhysicalChargeComplete': False, 'componentValuesNotAdditive': True}
    except Exception as error:
        return {'available': False, 'errorType': type(error).__name__}

ROOT = Path('/home/jwk/agent')

CORE = '32ce41c0ac6436198860f888e07ef9793e58dc40'

NODE = MODE = SEED = OBSERVER = None
LOWERS = []
LAST_LOWER = None
LAST_LOWER_AT = 0


def configure(node, mode, seed, observer):
    global NODE, MODE, SEED, OBSERVER, LOWERS
    need(node in ('node-a', 'node-b') and mode in ('off', 'lazy'), 'Explicit ordinary/lazy mode required')
    NODE, MODE, SEED, OBSERVER = node, mode, seed, observer
    selected = {}
    repository = Path(seed['repository'])
    for template in seed['templates']:
        for layer in template['rootfsLayers']:
            path = repository / 'managed-layers' / (layer['digest'].replace(':', '_') + '.overlaybd.commit')
            meta = path.stat()
            need(path.resolve(strict=True) == path and meta.st_uid == 1204 and stat.S_ISREG(meta.st_mode)
                 and meta.st_size == layer['size'], 'Bound lower file changed')
            key = (meta.st_dev, meta.st_ino)
            row = {'path': str(path), 'dev': meta.st_dev, 'inode': meta.st_ino, 'size': meta.st_size,
                   'mtime': meta.st_mtime_ns, 'ctime': meta.st_ctime_ns, 'digest': layer['digest']}
            need(key not in selected or selected[key] == row, 'Aliased lower identity differs')
            selected[key] = row
    LOWERS = list(selected.values())
    need(0 < len(LOWERS) <= 64, 'Unexpected unique four-template lower inventory')


def lower_cache(evict=False):
    rows = []
    began = time.time_ns()
    page = os.sysconf('SC_PAGESIZE')
    for row in LOWERS:
        fd = os.open(row['path'], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            actual = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            need(actual == tuple(row[k] for k in ('dev', 'inode', 'size', 'mtime', 'ctime')), 'Lower identity changed')
            if evict:
                # Only this experiment's independently copied, immutable files.
                need(Path(row['path']).is_relative_to(Path(SEED['repository'])), 'Eviction outside own repository')
                os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
            count = OBSERVER.resident_pages(fd, before.st_size, page)
            after = os.fstat(fd)
            need(actual == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'Lower changed during mincore')
            rows.append({'digest': row['digest'], 'dev': row['dev'], 'inode': row['inode'],
                         'fileBytes': before.st_size, 'residentBytes': count * page,
                         'pageSpanBytes': ((before.st_size + page - 1) // page) * page})
        finally:
            os.close(fd)
    return {'available': True, 'startNs': began, 'endNs': time.time_ns(), 'files': rows,
            'residentBytes': sum(row['residentBytes'] for row in rows), 'pageBytes': page,
            'scope': 'unique_ordinary_rootfs_lower_files_whole_file_residency_not_access_intersection',
            'evictionRequested': evict, 'globalCacheDropped': False, 'contentRead': False, 'atomicSnapshot': False}


def rpc(path, request):
    import struct
    import socket
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(10); stream.connect(str(path))
        _, uid, _ = struct.unpack('3i', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        need(uid == 1204, 'Unexpected provider socket peer')
        raw = json.dumps(request, separators=(',', ':')).encode()
        stream.sendall(struct.pack('>I', len(raw)) + raw)
        def exact(length):
            value = bytearray()
            while len(value) < length:
                part = stream.recv(length - len(value)); need(part, 'Short provider reply'); value.extend(part)
            return bytes(value)
        length = struct.unpack('>I', exact(4))[0]
        need(0 < length <= 4096, 'Oversized provider metadata')
        return json.loads(exact(length))


def provider_metrics(node, observer):
    if MODE == 'off':
        return {'available': True, 'enabled': False, 'logicalRequestBudgetBytes': 0,
                'sdkReportedBackingCoverageBytes': 0, 'physicalUBChargedBytes': None,
                'scope': 'this_round_lazy_pool_absent_other_providers_excluded'}
    result = {'available': False, 'enabled': True, 'coverageIsPhysicalCharge': False, 'physicalUBChargedBytes': None}
    try:
        fields = unit_fields('jwk-ub-lazy-four-' + node + '-v1.service')
        need(fields.get('ActiveState') == 'active' and fields.get('User') == fields.get('Group') == 'jwk', 'Lazy provider not active')
        pid = int(fields['MainPID']); start = ticks(pid)
        work = ROOT / ('r/lazy4-a-v1/provider' if node == 'node-a' else 'r/lazy4-b-v1/provider')
        journal = load(work / 'owner.json')
        need(journal.get('mode') == 'stored-lazy' and journal.get('state') == 'serving', 'Lazy provider generation unresolved')
        status = rpc(work / 'control.sock', {'operation': 'status'})
        need(status.get('state') != 'refused', 'Provider status refused')
        result.update(available=True, pid=pid, startTicks=start, cacheId=journal['cacheId'], pool=journal['pool'],
                      sdkReportedBackingCoverageBytes=journal.get('backingCoverageBytes'),
                      logicalRequestBudgetBytes=journal['pool']['mappingBytes'], counters=status,
                      wholeProcess=observer.whole_process_metrics(pid, start),
                      cgroup=cgroup_memory(fields['ControlGroup'], 'provider_not_complete_UB_physical_cost'))
        need(ticks(pid) == start and int(unit_fields('jwk-ub-lazy-four-' + node + '-v1.service')['MainPID']) == pid,
             'Lazy provider changed during sampling')
    except Exception as error:
        result.update(available=False, errorType=type(error).__name__)
    return result


def binding_contract(config, expected, mode, index):
    lowers = config.get('lowers')
    need(isinstance(lowers, list) and len(lowers) == len(expected), 'Actual Guest lower count differs')
    references = {} if mode == 'off' else {r['layerDigest']: r for r in index['replicas']}
    for actual, layer in zip(lowers, expected):
        need(actual['digest'] == layer['digest'] and actual['size'] == layer['size'], 'Actual Guest committed lower order differs')
        if mode == 'off':
            need(not actual.get('ub'), 'Baseline unexpectedly bound to UB')
        else:
            need(layer['digest'] in references and actual.get('ub') == references[layer['digest']]
                 and actual['ub'].get('allowRepositoryFallback') is False, 'Missing or unexpected UB binding/fallback')
    return True


def verify_bindings(api, observer, base, jobs, seed, mode):
    if os.geteuid()!=0:
        value=root_observation()['bindingEvidence']
        need(value['mode']==mode and set(value['guests'])=={j['sandboxId'] for j in jobs},'Root observation cohort differs')
        return value
    index = None
    if mode == 'lazy':
        work = ROOT / ('r/lazy4-a-v1/provider' if NODE == 'node-a' else 'r/lazy4-b-v1/provider')
        index = load(work / 'runtime-index.json')
        need(index.get('version') == 1 and index.get('state') == 'ready', 'Lazy runtime index not ready')
    expected_jobs = {j['sandboxId']: j for j in jobs}
    found = {}
    api.stable()
    for pid in observer.find_firecrackers(api.pid):
        proc = Path('/proc') / str(pid)
        stderr = Path(os.readlink(proc / 'fd/2'))
        if stderr.name != 'firecracker-stderr.log' or stderr.parent.parent != base / 'logs/firecracker':
            continue
        sid = stderr.parent.name
        if sid not in expected_jobs:
            continue
        need(sid not in found, 'Duplicate Guest process')
        start = ticks(pid)
        cwd = (proc / 'cwd').resolve(strict=True)
        need(cwd.is_relative_to(ROOT / 'r') and cwd.name.startswith('agentenv-fc-'), 'Unexpected FC path')
        path = cwd / 'overlaybd/image.json'
        raw = read(path)
        config = json.loads(raw)
        expected = seed['templates'][expected_jobs[sid]['templateIndex']]['rootfsLayers']
        binding_contract(config, expected, mode, index)
        if mode == 'off':
            for actual, layer in zip(config['lowers'], expected):
                p = observer.cache_path(actual['file'], path.parent, (cwd, base / 'state'))
                desired = Path(seed['repository']) / 'managed-layers' / (layer['digest'].replace(':', '_') + '.overlaybd.commit')
                need((p.stat().st_dev, p.stat().st_ino, p.stat().st_size) ==
                     (desired.stat().st_dev, desired.stat().st_ino, layer['size']), 'Baseline lower is not the independent copied input')
        need(ticks(pid) == start, 'Guest changed during binding check')
        found[sid] = {'pid': pid, 'startTicks': start, 'imageConfigSha256': hashlib.sha256(raw).hexdigest(),
                      'lowerCount': len(expected), 'variant': mode}
    need(set(found) == set(expected_jobs) and len(found) == 8, 'Every actual Guest lower must be bound')
    api.stable()
    return {'status': 'EIGHT_ACTUAL_GUEST_ROOTFS_BINDINGS_VERIFIED', 'guests': found,
            'mode': mode, 'nativeDax': False, 'repositoryFallback': False if mode == 'lazy' else None}


def sample_node(api, observer, base, node, phase, sids):
    global LAST_LOWER, LAST_LOWER_AT
    start = time.time_ns()
    root=root_observation()
    need(set(root['bindingEvidence']['guests'])==set(sids) and root['bindingEvidence']['mode']==MODE,'Root sample scope differs')
    ram = root['ram']
    fresh = LAST_LOWER is None or time.monotonic() - LAST_LOWER_AT >= 15 or phase != 'replay_window'
    if fresh:
        LAST_LOWER = lower_cache()
        LAST_LOWER_AT = time.monotonic()
    provider=provider_metrics(node,observer)
    if provider.get('available') and root.get('providerProcess'):
        need(provider['pid']==root['providerProcess']['pid'] and provider['startTicks']==root['providerProcess']['startTicks'],
             'Provider process changed between observations')
        provider['wholeProcess']=root['providerProcess']['wholeProcess']
    return {'phase': phase, 'startNs': start, 'endNs': time.time_ns(), 'ram': ram,
            'runtimeCharge': root['runtimeCharge'], 'provider': provider,
            'rootfsLowerFiles': LAST_LOWER, 'rootfsLowerFreshSample': fresh, 'atomicSnapshot': False}


def root_observation():
    path=ROOT/'lazy-four/lazy_four_root_client.py'
    need(hashlib.sha256(read(path)).hexdigest()==ROOT_CLIENT_SHA,'Root mailbox client changed')
    spec=importlib.util.spec_from_file_location('scoped_root_client',path)
    client=importlib.util.module_from_spec(spec);spec.loader.exec_module(client)
    result=client.request('observe')
    need(result['result']['state']=='scoped-readonly-observation','Unexpected root result')
    return result['result']

ROOT_CLIENT_SHA='4cd0f7f0da7ff1505be8b7e81c8c437a85f1bcf140d965940f7a2d5e6223b213'
