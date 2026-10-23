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

def provider_metrics(node, observer):
    result = {'available': False, 'scope': 'new_provider_process_and_cgroup_only',
              'physicalUBChargedBytes': None, 'coverageIsPhysicalCharge': False,
              'deviceMappingsMayBeUncharged': True}
    try:
        fields = unit_fields('jwk-ub-four-rootfs-' + node + '-v1.service')
        need(fields.get('ActiveState') == 'active' and fields.get('User') == fields.get('Group') == 'jwk',
             'New provider unit is not active under the expected user')
        pid = int(fields['MainPID'])
        need(pid > 1, 'Unexpected provider PID')
        start = ticks(pid)
        session = ROOT / ('r/up4-a-v1' if node == 'node-a' else 'r/up4-b-v1')
        prepared = load(session / 'prepared.json')
        owner = load(session / 'provider/owner.json')
        need(prepared.get('node') == node and prepared.get('sourceImage') == SOURCE
             and owner.get('state') == 'serving' and owner.get('format') == 'native-raw-v1'
             and owner.get('role') == ('publish' if node == 'node-a' else 'import'),
             'Provider journal does not identify the expected serving generation')
        rows = owner.get('objects') if node == 'node-a' else owner.get('imports')
        need(isinstance(rows, list) and 0 < len(rows) <= 8, 'Provider mapping evidence unavailable')
        values = [row.get('backing_coverage_bytes') for row in rows]
        coverage = sum(values) if all(type(v) is int and v > 0 for v in values) else None
        result.update(available=True, pid=pid, startTicks=start,
                      wholeProcess=observer.whole_process_metrics(pid, start),
                      cgroup=cgroup_memory(fields['ControlGroup'], scope='provider_unit_charge_not_complete_device_memory_cost'),
                      sdkReportedBackingCoverageBytes=coverage,
                      logicalRequestBudgetBytes=prepared.get('logicalBudgetBytes'),
                      manifestSha256=owner.get('manifestSha256'),
                      allocationRecords=len(owner.get('objects', [])))
        need(ticks(pid) == start and int(unit_fields('jwk-ub-four-rootfs-' + node + '-v1.service')['MainPID']) == pid,
             'Provider process changed during observation')
    except Exception as error:
        result.update(available=False, errorType=type(error).__name__,
                      reason=str(error)[:300] if isinstance(error, RuntimeError) else 'Provider observation unavailable or not started')
    return result

def sample_node(api, observer, base, node, phase, sids):
    start = time.time_ns()
    ram = observer.collect_ram(base, api.pid, api.ticks, sids)
    charge = cgroup_memory(api.cgroup)
    provider = provider_metrics(node, observer)
    return {'phase': phase, 'startNs': start, 'endNs': time.time_ns(), 'ram': ram,
            'runtimeCharge': charge, 'provider': provider, 'atomicSnapshot': False}

ROOT = Path('/home/jwk/agent')
CORE = '32ce41c0ac6436198860f888e07ef9793e58dc40'
