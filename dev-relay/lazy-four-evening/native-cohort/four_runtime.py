"""Scoped Runtime API and read-only metrics for the native four cohort."""
import argparse

import concurrent.futures

import hashlib

import http.client

import importlib.util

import json

import os

from pathlib import Path, PurePosixPath

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

def mounts(text):
    result=[]
    def decode(value):
        return re.sub(r'\\([0-7]{3})',lambda m:chr(int(m[1],8)),value)
    for line in text.splitlines():
        left,sep,right=line.partition(' - ')
        a,b=left.split(),right.split()
        if not sep or len(a)<6 or len(b)<3:continue
        if b[0]=='cgroup2' or b[0]=='cgroup' and 'memory' in b[2].split(','):
            result.append({'version':2 if b[0]=='cgroup2' else 1,'root':decode(a[3]),'mount':decode(a[4])})
    return sorted(result,key=lambda item:-item['version'])

def candidates(group,mountinfo):
    path=PurePosixPath(group)
    if not path.is_absolute() or '..' in path.parts or '\0' in group:
        raise ValueError('Invalid unit cgroup path')
    for item in mounts(mountinfo):
        base=PurePosixPath(item['root'])
        if not base.is_absolute() or '..' in base.parts:continue
        try:relative=path.relative_to(base)
        except ValueError:continue
        declared_mount=PurePosixPath(item['mount'])
        if not declared_mount.is_absolute() or '..' in declared_mount.parts:continue
        mount=Path(item['mount'])
        yield item['version'],mount,mount.joinpath(*relative.parts)

def cgroup_memory(group,scope='runtime_unit_charge',mountinfo=None):
    errors=[]
    try:
        text=Path('/proc/self/mountinfo').read_text() if mountinfo is None else mountinfo
        places=list(candidates(group,text))
    except (OSError,ValueError) as error:
        return {'available':False,'currentBytes':None,'errorType':type(error).__name__,'scope':scope}
    for version,mount,directory in places:
        try:
            resolved_mount=mount.resolve(strict=True)
            resolved=directory.resolve(strict=True)
            if not resolved.is_relative_to(resolved_mount):raise ValueError('Cgroup path escapes its mounted hierarchy')
            current_path=resolved/('memory.current' if version==2 else 'memory.usage_in_bytes')
            current=int(current_path.read_text().strip())
            if current<0:raise ValueError('Invalid memory charge')
            raw=dict(line.split() for line in (resolved/'memory.stat').read_text().splitlines())
            if version==2:
                stats={k:int(raw[k]) for k in ('anon','file','kernel','shmem','slab') if k in raw}
            else:
                # Keep v1's original names. rss/cache are not an exact v2 anon/file decomposition.
                stats={k:int(raw[k]) for k in ('rss','cache','mapped_file','swap','total_rss','total_cache','total_swap') if k in raw}
            return {'available':True,'version':version,'currentBytes':current,'statBytes':stats,
                    'scope':scope,'source':str(current_path),'UBPhysicalChargeComplete':False,'componentValuesNotAdditive':True}
        except (OSError,ValueError) as error:errors.append({'version':version,'errorType':type(error).__name__})
    return {'available':False,'currentBytes':None,'scope':scope,'errors':errors,
            'reason':'No readable unit memory controller; not a zero-memory result'}

PROVIDER_CONTEXT=None

def configure_provider(path,node):
    global PROVIDER_CONTEXT
    raw=read(Path(path));plan=json.loads(raw)
    need(plan.get('node')==node and plan.get('version')==1
         and plan.get('bootId')==Path('/proc/sys/kernel/random/boot_id').read_text().strip()
         and re.fullmatch(r'jwk-native-retained-node-[ab]-[0-9a-f]{12}\.service',plan.get('unit','')),
         'Native provider plan node/boot/unit differs')
    work=Path(plan['request']['output'])/'provider'
    need(work.is_absolute() and work.is_relative_to(ROOT) and work.resolve(strict=True)==work,'Provider directory differs')
    owner=load(work/'owner.json');manifest=load(work/'replicas.json')
    need(manifest.get('version')==1 and manifest.get('mode')=='pmem'
         and isinstance(manifest.get('replicas'),list) and 1<=len(manifest['replicas'])<=8,'Invalid native replica manifest')
    identity='sha256:'+hashlib.sha256(json.dumps(manifest,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()
    need(owner.get('state')=='serving' and owner.get('mode')=='pmem' and owner.get('format')=='native-raw-v1'
         and owner.get('role')==('publish' if node=='node-a' else 'import')
         and owner.get('ownerId')==manifest.get('ownerId') and owner.get('manifestSha256')==identity,
         'Native provider is not serving the declared generation')
    fields=unit_fields(plan['unit']);pid=int(fields['MainPID'])
    need(fields.get('ActiveState')=='active' and fields.get('User')==fields.get('Group')=='jwk' and pid>1,
         'Provider unit is not active as the expected user')
    PROVIDER_CONTEXT={'node':node,'path':str(path),'planSha256':hashlib.sha256(raw).hexdigest(),'plan':plan,
                      'pid':pid,'ticks':ticks(pid),'ownerId':owner['ownerId'],'manifestSha256':identity,'socket':str(work/'data.sock')}
    return {k:PROVIDER_CONTEXT[k] for k in ('node','pid','ticks','ownerId','manifestSha256','socket')}

def provider_metrics(node,observer):
    result={'available':False,'scope':'declared_native_provider_process_and_cgroup',
            'physicalUBChargedBytes':None,'coverageIsPhysicalCharge':False,'deviceMappingsMayBeUncharged':True}
    try:
        context=PROVIDER_CONTEXT
        need(context is not None and context['node']==node,'No declared provider metrics context')
        plan=context['plan'];unit=plan['unit'];work=Path(plan['request']['output'])/'provider'
        need(hashlib.sha256(read(Path(context['path']))).hexdigest()==context['planSha256'],'Provider plan changed')
        fields=unit_fields(unit);pid=context['pid'];start=context['ticks'];owner=load(work/'owner.json')
        need(fields.get('ActiveState')=='active' and int(fields['MainPID'])==pid and ticks(pid)==start
             and owner.get('state')=='serving' and owner.get('ownerId')==context['ownerId']
             and owner.get('manifestSha256')==context['manifestSha256'],'Provider identity changed')
        rows=owner.get('objects') if node=='node-a' else owner.get('imports')
        need(isinstance(rows,list) and 0<len(rows)<=8,'Mapping records unavailable')
        coverage=[row.get('backing_coverage_bytes') for row in rows]
        result.update(available=True,pid=pid,startTicks=start,ownerId=context['ownerId'],manifestSha256=context['manifestSha256'],
            wholeProcess=observer.whole_process_metrics(pid,start),
            cgroup=cgroup_memory(fields['ControlGroup'],scope='provider_charge_not_complete_device_cost'),
            sdkReportedBackingCoverageBytes=sum(coverage) if all(type(v) is int and v>0 for v in coverage) else None,
            logicalRequestBudgetBytes=plan['request']['logicalBudgetBytes'],allocationRecords=len(owner.get('objects',[])))
        need(ticks(pid)==start and int(unit_fields(unit)['MainPID'])==pid,'Provider changed during collection')
    except Exception as error:
        result.update(available=False,errorType=type(error).__name__,reason=str(error)[:300] if isinstance(error,RuntimeError) else 'Provider metrics unavailable')
    return result


def sample_node(api, observer, base, node, phase, sids):
    start = time.time_ns()
    ram = observer.collect_ram(base, api.pid, api.ticks, sids)
    charge = cgroup_memory(api.cgroup)
    provider = provider_metrics(node, observer)
    return {'phase': phase, 'startNs': start, 'endNs': time.time_ns(), 'ram': ram,
            'runtimeCharge': charge, 'provider': provider, 'atomicSnapshot': False}

ROOT = Path('/home/jwk/agent')
CORE = '5e6621c9c9d2e347959a61a46c7f6d99688eeb55'
