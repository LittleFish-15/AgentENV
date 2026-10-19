"""Prepare one bounded original-runtime parent snapshot from a pinned OCI image.

Host downloads with existing regctl; isolated Runtime receives a local OCI path.
One cold create maximum, no create retry. Own parent is deleted after capture.
No UB, service/permission changes, benchmark replay, or shared-memory claims.
"""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit, urlencode
import uuid

ROOT = Path('/home/jwk/agent')
BASE = ROOT / 'deployments/agentenv-ae9c626-baseline'
UNIT = 'jwk-aenv-ae9c626-node-a.service'
MAX_IMAGE_BYTES = 512 * 1024**2
PENDING = ROOT / 'relay/cow-parent-node-a.pending.json'
ID = re.compile(r'[A-Za-z0-9_-]{1,128}')
NETWORK_KEYS = ('HTTP_PROXY', 'http_proxy', 'HTTPS_PROXY', 'https_proxy', 'ALL_PROXY', 'all_proxy',
                'NO_PROXY', 'no_proxy', 'SSL_CERT_FILE', 'SSL_CERT_DIR')


def network_environment(source):
    """Use existing user routes/trust paths; never invent a proxy or DNS server."""
    env = {k: source[k] for k in NETWORK_KEYS if source.get(k)}
    inherited = sorted(env)
    mapped = []
    # Go's ProxyFromEnvironment uses HTTP(S)_PROXY, unlike curl's ALL_PROXY.
    # Use only a route already configured by the caller, when scheme-specific
    # settings are absent. Keep existing NO_PROXY exclusions.
    fallback = env.get('all_proxy') or env.get('ALL_PROXY')
    if fallback:
        for upper, lower in (('HTTP_PROXY', 'http_proxy'), ('HTTPS_PROXY', 'https_proxy')):
            if not env.get(upper) and not env.get(lower):
                need(urlsplit(fallback).scheme.lower() in ('http', 'https', 'socks5', 'socks5h'),
                     'Existing ALL_PROXY has unsupported scheme; value withheld')
                env[upper] = fallback
                mapped.append(upper)
    for key in ('NO_PROXY', 'no_proxy'):
        previous = env.get(key) or env.get('no_proxy' if key == 'NO_PROXY' else 'NO_PROXY', '')
        parts = [x.strip() for x in previous.split(',') if x.strip()]
        env[key] = ','.join(dict.fromkeys(parts + ['127.0.0.1', 'localhost', '::1']))
    return env, {'inherited_variable_names': inherited, 'all_proxy_mapped_to': mapped,
                 'proxy_values_in_report': False, 'system_dns_modified': False,
                 'tls_verification_disabled': False, 'docker_certificate_import': False}


def redact_child_output(text, env):
    for key in NETWORK_KEYS:
        value = env.get(key)
        if value and len(value) >= 8:
            text = text.replace(value, '[NETWORK_ENV_VALUE]')
    text = re.sub(r'e2b_[A-Za-z0-9._~-]+', '[REDACTED]', text)
    text = re.sub(r'(?i)(https?|socks5h?)://[^/\s@]+@', r'\1://[REDACTED]@', text)
    text = re.sub(r'https?://\S+\?\S+', '[URL query withheld]', text)
    return '\n'.join('[REDACTED authentication line]' if re.search(
        r'authorization|password|secret|bearer\s|access_token\s*[:=]', line, re.I)
        else line for line in text.splitlines())


class ChildFailure(RuntimeError):
    def __init__(self, log, code, stdout, stderr):
        super().__init__('Child command failed; diagnostics included: ' + log.name)
        self.diagnostics = {'stdout_file': log.name, 'stderr_file': log.stem + '.stderr.log',
                            'exit_code': code, 'stdout_tail': stdout, 'stderr_tail': stderr}


def need(ok, text):
    if not ok:
        raise RuntimeError(text)


def safe(path):
    path = Path(path)
    need(path.is_absolute() and path.is_relative_to(ROOT) and path.resolve() == path, 'Outside or redirected path')
    if path.exists():
        need(path.lstat().st_uid == 1204, 'Unexpected file owner')
    return path


def read(path, limit=1024 * 1024):
    safe(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        m = os.fstat(f.fileno())
        need(stat.S_ISREG(m.st_mode) and m.st_uid == 1204 and m.st_size <= limit, 'Unexpected file metadata')
        data = f.read(limit + 1)
        need(len(data) <= limit, 'Input grew beyond limit')
        return data


def save(path, obj):
    safe(path)
    data = (json.dumps(obj, indent=2) + '\n').encode()
    temp = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    with temp.open('xb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, path)


def runtime_pid():
    r = subprocess.run(['/usr/bin/systemctl', 'show', UNIT, '--property=ActiveState,MainPID,User,Group'],
                       capture_output=True, text=True, timeout=10, check=True)
    fields = dict(x.split('=', 1) for x in r.stdout.splitlines() if '=' in x)
    need(fields.get('ActiveState') == 'active' and fields.get('User') == fields.get('Group') == 'jwk', 'Original runtime not healthy/expected')
    pid = int(fields.get('MainPID', 0))
    need(pid > 1, 'Invalid runtime PID')
    ticks = Path('/proc/' + str(pid) + '/stat').read_text().rsplit(')', 1)[1].split()[19]
    return pid, ticks


class Api:
    def __init__(self):
        self.key = read(BASE / 'config/api-key', 1024).decode().strip()
        need(re.fullmatch(r'e2b_[A-Za-z0-9._~-]+', self.key), 'Invalid API key format; value withheld')
        self.identity = runtime_pid()

    def call(self, method, path, data=None, timeout=20):
        need(runtime_pid() == self.identity, 'Original service changed; no request sent')
        allowed = path in ('/health', '/sandboxes-cold') or re.fullmatch(r'/sandboxes/[A-Za-z0-9_-]+(?:/snapshots)?', path)
        allowed = allowed or (method == 'GET' and re.fullmatch(
            r'/v2/sandboxes\?metadata=cow_parent_run%3D[0-9a-f]{32}&limit=2', path))
        need(allowed and method in ('GET', 'POST', 'DELETE'), 'API route outside experiment')
        conn = http.client.HTTPConnection('127.0.0.1', 18080, timeout=timeout)
        try:
            body = json.dumps(data).encode() if data is not None else None
            conn.request(method, path, body=body, headers={'X-API-Key': self.key, 'Content-Type': 'application/json'})
            response = conn.getresponse()
            raw = response.read(1024 * 1024 + 1)
            need(len(raw) <= 1024 * 1024, 'API reply exceeds limit')
            return response.status, json.loads(raw) if raw else None
        finally:
            conn.close()


def error_summary(body, key):
    if not isinstance(body, dict):
        return {'message': 'Non-object response body withheld'}
    message = body.get('message', '')
    if not isinstance(message, str):
        message = 'Non-text error message withheld'
    message = message.replace(key, '[REDACTED]')
    message = re.sub(r'e2b_[A-Za-z0-9._~-]+', '[REDACTED]', message)
    message = re.sub(r'https?://\S+\?\S+', '[URL query withheld]', message)
    return {'code': body.get('code') if isinstance(body.get('code'), int) else None,
            'message': message[:3000]}


def known_size_rejection(prior, args):
    error = prior.get('create_error') or {}
    return (prior.get('revision') == 'cow-parent-once-v2' and prior.get('node') == 'node-a'
            and prior.get('create_http_status') == 400 and error.get('code') == 400
            and prior.get('create_calls') == 1 and prior.get('parent_id') is None
            and prior.get('snapshot_id') is None and prior.get('image') == args.image
            and prior.get('Guest_workdir') == args.workdir and prior.get('warm_module') == args.warm_module
            and isinstance(prior.get('run_id'), str) and re.fullmatch(r'[0-9a-f]{32}', prior['run_id']) is not None
            and re.search(r'requested overlaybd runtime virtual size 2147483648 is smaller than base virtual size 68719476736; shrinking is disabled',
                          str(error.get('message', ''))) is not None)


def reconcile_size_rejection(api, prior, args, work):
    need(known_size_rejection(prior, args), 'Prior attempt is not the reviewed disk-size rejection')
    old_dir = safe(Path(prior['report_directory']))
    need(old_dir.parent == ROOT / 'relay/reports' and old_dir.name.startswith('node-a-cow-parent-'), 'Unexpected previous report path')
    need(json.loads(read(old_dir / 'return.json')) == prior, 'Pending and completed report differ; preserved')
    query = '/v2/sandboxes?' + urlencode({'metadata': 'cow_parent_run=' + prior['run_id'], 'limit': 2})
    status, rows = api.call('GET', query)
    need(status == 200 and isinstance(rows, list), 'Cannot reconcile previous request; no new create')
    need(not rows, 'Previous run still has a visible sandbox; preserve it, no new create/delete')
    image = safe(old_dir / 'image')
    need(image.is_dir(), 'Previously verified OCI directory missing')
    verification = verify_layout(image, args.image.split('@')[1])
    save(work / 'previous-pending.json', prior)
    return image, verification, {
        'prior_run_id': prior['run_id'], 'prior_http_status': 400,
        'classification': 'KNOWN_SIZE_REJECTION_NO_VISIBLE_MATCHING_SANDBOX',
        'matching_sandboxes': 0, 'query_includes_all_states': True,
        'prior_report_preserved': True, 'prior_pending_backup': str(work / 'previous-pending.json'),
        'prior_runtime_directory_removed': False, 'new_attempt_limit': 1}


def parent_layer_inventory(snapshot_id):
    """Capture stored/allocated bytes, not Guest physical sharing or cache sizes."""
    result = {'phase': 'after_parent_capture_before_replay',
              'scope': 'stored_layer_metadata_only_no_shared_page_claim',
              'snapshot_id': snapshot_id, 'content_hashes_verified': False}
    try:
        repo = BASE / 'state/snapshot-store'
        record = json.loads(read(repo / 'catalog/records' / (snapshot_id + '.json')))
        need(record.get('id') == snapshot_id and isinstance(record.get('committed'), dict), 'Committed snapshot record mismatch')
        committed = record['committed']
        for kind in ('memory', 'rootfs'):
            rows = []
            for item in committed.get(kind + '_layers', []):
                origin = 'Managed' if kind == 'memory' else next(iter(item), '')
                layer = item if kind == 'memory' else item.get(origin, {})
                digest = layer.get('digest', '')
                need(re.fullmatch(r'sha256:[0-9a-f]{64}', digest), 'Unexpected committed digest')
                row = {'origin': origin, 'digest': digest, 'stored_bytes_declared': layer.get('size')}
                if origin == 'Managed':
                    path = safe(repo / 'managed-layers' / (digest.replace(':', '_') + '.overlaybd.commit'))
                    try:
                        m = path.stat()
                        need(stat.S_ISREG(m.st_mode), 'Managed layer is not a regular file')
                        row.update(path=str(path), file_bytes=m.st_size, allocated_file_bytes=m.st_blocks * 512,
                                   dev=m.st_dev, inode=m.st_ino, mtime_ns=m.st_mtime_ns)
                    except Exception as e:
                        row['file_measurement'] = {'available': False, 'error_type': type(e).__name__}
                else:
                    row['file_measurement'] = {'available': False, 'reason': 'EXTERNAL_PLACEMENT_NOT_RESOLVED'}
                rows.append(row)
            result[kind] = rows
        result['available'] = True
    except Exception as e:
        result.update(available=False, error_type=type(e).__name__)
    return result


def verify_layout(layout, digest):
    def blob(d, size=None):
        need(re.fullmatch(r'sha256:[0-9a-f]{64}', d), 'Unsupported blob digest')
        path = layout / 'blobs/sha256' / d.split(':')[1]
        safe(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as f:
            m = os.fstat(f.fileno())
            need(stat.S_ISREG(m.st_mode) and m.st_uid == 1204 and m.st_size <= MAX_IMAGE_BYTES, 'Invalid OCI blob')
            need(size is None or m.st_size == size, 'OCI blob length differs')
            h = hashlib.sha256()
            for part in iter(lambda: f.read(1024 * 1024), b''):
                h.update(part)
        need('sha256:' + h.hexdigest() == d, 'OCI blob hash differs')
        return path
    manifest = json.loads(read(blob(digest)))
    layers = manifest.get('layers', [])
    need(isinstance(layers, list) and 0 < len(layers) <= 32, 'Invalid layer count')
    total = sum(x['size'] for x in layers) + manifest['config']['size']
    need(0 < total <= MAX_IMAGE_BYTES, 'Image exceeds 512MiB compressed input budget')
    cfg = manifest['config']
    config = json.loads(read(blob(cfg['digest'], cfg['size'])))
    need(config.get('os') == 'linux' and config.get('architecture') == 'arm64', 'Image is not Linux ARM64')
    for layer in layers:
        blob(layer['digest'], layer['size'])
    return {'manifest_digest': digest, 'layer_count': len(layers), 'verified_compressed_bytes': total,
            'architecture': 'arm64', 'hashing_phase': 'preparation_before_memory_measurement'}


def checked_process(command, env, log, timeout):
    stderr_path = log.with_name(log.stem + '.stderr.log')
    code = None
    try:
        with log.open('wb') as output, stderr_path.open('wb') as error:
            r = subprocess.run([str(x) for x in command], stdin=subprocess.DEVNULL,
                               stdout=output, stderr=error, env=env, timeout=timeout)
        code = r.returncode
    except subprocess.TimeoutExpired:
        code = 'TIMEOUT'
    # stderr is diagnostic text, never manifest content. Bound and sanitize it
    # before returning or including it in the report; keep successful stdout
    # byte-for-byte intact for content-addressed manifest verification.
    def sanitized_log(path):
        with path.open('rb') as f:
            f.seek(0, os.SEEK_END)
            length = f.tell()
            f.seek(max(0, length - 65536))
            text = redact_child_output(f.read(65536).decode(errors='replace'), env)
        path.write_text(('[EARLIER DIAGNOSTICS TRUNCATED]\n' if length > 65536 else '') + text)
    sanitized_log(stderr_path)
    if code != 0:
        sanitized_log(log)
        def tail(path):
            with path.open('rb') as f:
                f.seek(0, os.SEEK_END)
                f.seek(max(0, f.tell() - 6000))
                return redact_child_output(f.read(6000).decode(errors='replace'), env)
        raise ChildFailure(log, code, tail(log), tail(stderr_path))


WARM = '''import importlib,json,os,sys
os.chdir(sys.argv[1])
importlib.import_module(sys.argv[2])
print("COW_PARENT_WORKLOAD_IMPORT_OK")
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, help='Digest-pinned OCI reference')
    parser.add_argument('--workdir', required=True, help='Existing Guest working directory')
    parser.add_argument('--warm-module', required=True, help='Workload module imported in the parent')
    args = parser.parse_args()
    need(sys.platform == 'linux' and socket.gethostname() == 'server1' and os.uname().machine == 'aarch64', 'A/server1 ARM64 only')
    need(os.getuid() == os.geteuid() == 1204 and os.getgid() == os.getegid() == 1205, 'Ordinary jwk only')
    caps = re.findall(r'^(Cap(?:Inh|Prm|Eff|Amb)):\s*(\w+)$', Path('/proc/self/status').read_text(), re.M)
    need(len(caps) == 4 and all(int(v, 16) == 0 for k, v in caps), 'No collector capabilities allowed')
    need(os.environ.get('HOME') == '/home/jwk', 'Keep normal HOME')
    need(re.fullmatch(r'[a-z0-9.-]+/[A-Za-z0-9_./-]+@sha256:[0-9a-f]{64}', args.image), 'Use a pinned OCI reference')
    need(re.fullmatch(r'/[A-Za-z0-9_/-]+', args.workdir) and '..' not in Path(args.workdir).parts, 'Invalid Guest workdir')
    need(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]*', args.warm_module), 'Invalid import module')
    os.umask(0o077)
    import fcntl
    with open(safe(ROOT / 'relay/cow-parent-node-a.lock'), 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        prior = json.loads(read(PENDING)) if PENDING.exists() else None
        if prior and not known_size_rejection(prior, args):
            print('BEGIN_RETURN_REPORT')
            print(json.dumps({'status': 'PARENT_RECEIPT_EXISTS_NO_NEW_CREATE', 'prior': prior}, indent=2))
            print('END_RETURN_REPORT')
            return 1
        work = Path(tempfile.mkdtemp(prefix='node-a-cow-parent-', dir=safe(ROOT / 'relay/reports')))
        report = {'revision': 'cow-parent-once-v3', 'node': 'node-a', 'report_directory': str(work),
                  'image': args.image, 'Guest_workdir': args.workdir, 'warm_module': args.warm_module,
                  'run_id': uuid.uuid4().hex, 'SDK_called': False, 'services_modified': False,
                  'cow_validation_executed': False, 'cpu_count': 1, 'memory_mib': 512,
                  'disk_logical_mib_requested': None, 'disk_policy': 'INHERIT_BASE_NO_RESIZE',
                  'disk_logical_mib_observed': None, 'max_cold_create_calls': 1,
                  'create_calls': 0, 'snapshot_id': None, 'parent_id': None,
                  'parent_deleted': False, 'create_outcome_uncertain': False,
                  'started_unix': time.time()}
        api = None
        try:
            need(os.statvfs(ROOT).f_bavail * os.statvfs(ROOT).f_frsize >= 8 * 1024**3, 'Need 8GiB available workspace space')
            receipt = json.loads(read(BASE / 'installation.json'))
            need(receipt.get('node') == 'node-a' and receipt.get('commit') == 'ae9c62693839ce7effa2b45df31c0039ae4f9fbc', 'Original installation identity differs')
            api = Api()
            need(api.call('GET', '/health')[0] == 204, 'Original health failed')
            reused_image = None
            if prior:
                print('PHASE=reconcile_previous_size_rejection', flush=True)
                reused_image, report['image_verification'], report['previous_attempt_resolution'] = reconcile_size_rejection(api, prior, args, work)
            regctl = safe(BASE / 'deps/regctl/v0.11.5/regctl')
            need(regctl.is_file(), 'Existing regctl missing; no installation attempted')
            for name in ('tmp', 'cache', 'docker', 'cli-config/aenv'):
                (work / name).mkdir(parents=True)
            save(work / 'docker/config.json', {'auths': {}})
            # regctl v0.11.5 Config.IncDockerCert/Cred: avoid root-owned Docker
            # directories; standard system CA verification remains enabled.
            save(work / 'regctl.json', {'incDockerCert': False, 'incDockerCred': False})
            env = {'HOME': '/home/jwk', 'USER': 'jwk', 'LOGNAME': 'jwk', 'LANG': 'C.UTF-8',
                   'PATH': str(BASE / 'native/bin') + ':/usr/bin:/bin',
                   'LD_LIBRARY_PATH': str(BASE / 'native/lib') + ':' + str(BASE / 'native/fallback/lib'),
                   'TMPDIR': str(work / 'tmp'), 'XDG_CACHE_HOME': str(work / 'cache'),
                   'XDG_CONFIG_HOME': str(work / 'cli-config'), 'DOCKER_CONFIG': str(work / 'docker'),
                   'REGCTL_CONFIG': str(work / 'regctl.json'), 'GOMAXPROCS': '2'}
            network_env, report['network_environment'] = network_environment(os.environ)
            env.update(network_env)
            expected = args.image.split('@')[1]
            if reused_image:
                image = reused_image
                report['image_downloaded_this_run'] = False
                print('PHASE=reuse_verified_local_oci', flush=True)
            else:
                print('PHASE=resolve_fixed_image_metadata', flush=True)
                checked_process([regctl, 'manifest', 'get', '--format', 'raw-body', args.image], env,
                                work / 'manifest.json', 60)
                raw = read(work / 'manifest.json')
                need('sha256:' + hashlib.sha256(raw).hexdigest() == expected, 'Manifest digest differs')
                manifest = json.loads(raw)
                need(0 < sum(x['size'] for x in manifest['layers']) + manifest['config']['size'] <= MAX_IMAGE_BYTES,
                     'Fixed image exceeds compressed byte budget')
                image = work / 'image'
                print('PHASE=download_one_image_to_local_oci', flush=True)
                checked_process([regctl, 'image', 'copy', '--platform', 'linux/arm64', args.image,
                                 'ocidir://' + str(image) + ':parent'], env, work / 'image-copy.log', 600)
                report['image_verification'] = verify_layout(image, expected)
                report['image_downloaded_this_run'] = True
            report['local_oci_directory'] = str(image)
            print('PHASE=one_original_parent_create', flush=True)
            if prior:
                need(json.loads(read(PENDING)) == prior, 'Prior pending changed during reconciliation; no create')
            else:
                need(not PENDING.exists(), 'A pending receipt appeared concurrently; no create')
            report.update(create_calls=1, create_outcome_uncertain=True)
            save(PENDING, report)
            status, body = api.call('POST', '/sandboxes-cold', {
                'image': 'ocidir://' + str(image) + '@' + expected,
                'cpuCount': 1, 'memoryMB': 512,
                'secure': True, 'autoPause': False, 'allowInternetAccess': False,
                'timeout': 900, 'metadata': {'cow_parent_run': report['run_id']}}, timeout=600)
            report['create_http_status'] = status
            if status != 201:
                report['create_error'] = error_summary(body, api.key)
            need(status == 201 and isinstance(body, dict), 'Cold create did not return 201; outcome retained for reconciliation')
            sid = body.get('sandboxID')
            need(isinstance(sid, str) and ID.fullmatch(sid), 'Invalid created sandbox identity')
            report.update(parent_id=sid, create_outcome_uncertain=False)
            actual_disk = body.get('diskSizeMB')
            report['disk_logical_mib_observed'] = actual_disk if isinstance(actual_disk, int) else None
            save(PENDING, report)
            # CLI consumes the same already-authorized loopback API key. Kept
            # only in this 0700 run directory and removed in finally.
            credentials = work / 'cli-config/aenv/credentials'
            credentials.write_text('url = "http://127.0.0.1:18080"\napi_key = ' + json.dumps(api.key) + '\n')
            print('PHASE=guest_workload_import', flush=True)
            checked_process([BASE / 'bin/aenv', 'exec', sid, 'python', '-c', WARM, args.workdir, args.warm_module],
                            env, work / 'guest-import.log', 60)
            need(b'COW_PARENT_WORKLOAD_IMPORT_OK' in read(work / 'guest-import.log'), 'Guest warmup did not confirm module import')
            print('PHASE=capture_fixed_parent_snapshot', flush=True)
            report['snapshot_capture_attempted'] = True
            save(PENDING, report)
            status, body = api.call('POST', '/sandboxes/' + sid + '/snapshots',
                                    {'name': 'jwk-cow-parent-' + report['run_id']}, timeout=300)
            report['snapshot_http_status'] = status
            if status not in (200, 201):
                report['snapshot_error'] = error_summary(body, api.key)
            need(status in (200, 201) and isinstance(body, dict), 'Snapshot capture reply not confirmed')
            snapshot = body.get('snapshotID')
            need(isinstance(snapshot, str) and ID.fullmatch(snapshot), 'Snapshot ID not confirmed')
            report['snapshot_id'] = snapshot
            report['parent_layer_inventory'] = parent_layer_inventory(snapshot)
            save(PENDING, report)
        except Exception as e:
            report['error'] = {'type': type(e).__name__, 'errno': getattr(e, 'errno', None),
                               'reason': str(e) if type(e) is RuntimeError else 'See own bounded logs; no create retry'}
            if isinstance(e, ChildFailure):
                report['error']['child_diagnostics'] = e.diagnostics
        finally:
            sid = report['parent_id']
            if sid and api:
                try:
                    status, detail = api.call('GET', '/sandboxes/' + sid)
                    if status == 404:
                        report['parent_deleted'] = True
                    else:
                        need(status == 200 and detail.get('metadata', {}).get('cow_parent_run') == report['run_id'], 'Parent ownership marker differs; no delete')
                        status, _ = api.call('DELETE', '/sandboxes/' + sid, timeout=90)
                        need(status in (200, 204, 404), 'Own parent delete not acknowledged')
                        report['parent_deleted'] = api.call('GET', '/sandboxes/' + sid)[0] == 404
                except Exception as e:
                    report['cleanup_error'] = {'type': type(e).__name__, 'detail': str(e) if type(e) is RuntimeError else 'Cleanup uncertain; preserve receipt'}
            credentials = work / 'cli-config/aenv/credentials'
            if credentials.exists():
                credentials.unlink()
            report['temporary_cli_credentials_removed'] = not credentials.exists()
        complete = report['snapshot_id'] and report['parent_deleted'] and not report.get('error')
        report['status'] = 'ORIGINAL_PARENT_SNAPSHOT_READY_PARENT_RELEASED' if complete else 'STOPPED_PARENT_PREPARATION_REVIEW_RECEIPT'
        report['finished_unix'] = time.time()
        save(work / 'return.json', report)
        if report['create_calls']:
            save(PENDING, report)
        print('BEGIN_RETURN_REPORT')
        print(json.dumps(report, indent=2))
        print('END_RETURN_REPORT')
        return 0 if complete else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as e:
        print('BEGIN_RETURN_REPORT')
        print(json.dumps({'status': 'STOPPED_PARENT_ENTRY', 'error_type': type(e).__name__,
                          'reason': str(e) if type(e) is RuntimeError else 'Entry failed'}))
        print('END_RETURN_REPORT')
        raise SystemExit(1)
