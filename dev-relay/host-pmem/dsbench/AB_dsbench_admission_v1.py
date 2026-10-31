"""DSBench P1 read-only admission. No image-layer download or SDK/service action."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import urllib.error
import urllib.parse
import urllib.request

HOST = 'swr.cn-north-4.myhuaweicloud.com'
NAMES = [
 'dsbench-analysis-00000001-2016-round-1-section-2-chip-off-the-old-block',
 'dsbench-analysis-00000005-2016-round-1-section-3-roll-the-dice',
 'dsbench-analysis-00000011-2014-round-2-purple-city',
 'dsbench-analysis-00000013-2017-round-2-late-again',
 'dsbench-analysis-00000028-2015-round-one-options-to-call',
 'dsbench-modeling-bike-sharing-demand', 'dsbench-modeling-nlp-getting-started',
 'dsbench-modeling-playground-series-s3e13', 'dsbench-modeling-spaceship-titanic',
 'dsbench-modeling-titanic']
ACCEPT = ', '.join(['application/vnd.oci.image.index.v1+json',
 'application/vnd.docker.distribution.manifest.list.v2+json',
 'application/vnd.oci.image.manifest.v1+json',
 'application/vnd.docker.distribution.manifest.v2+json'])


def allowed(url):
    u = urllib.parse.urlparse(url)
    if u.scheme != 'https' or u.hostname != HOST or u.username or u.password or u.port not in (None, 443):
        raise ValueError('Registry/auth URL outside the reviewed anonymous origin')


class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        allowed(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url, token=None):
    allowed(url)
    headers = {'Accept': ACCEPT, 'User-Agent': 'AgentENV-DSBench-admission-v1'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    with urllib.request.build_opener(Redirect()).open(
            urllib.request.Request(url, headers=headers), timeout=8) as response:
        raw = response.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError('Metadata exceeds 2MiB; image payload not fetched')
        observed = response.headers.get('Docker-Content-Digest')
        digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
        if observed and observed != digest:
            raise ValueError('Registry metadata digest mismatch')
        return json.loads(raw), digest


def manifest(name):
    prefix = 'https://' + HOST + '/v2/kunpeng-ai/' + name
    url = prefix + '/manifests/latest'
    token = None
    try:
        value, tag_digest = fetch(url)
    except urllib.error.HTTPError as error:
        if error.code != 401:
            raise
        challenge = error.headers.get('WWW-Authenticate', '')
        error.close()
        if not challenge.lower().startswith('bearer '):
            raise ValueError('Registry requires credentials; no local credentials read')
        fields = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
        realm = fields['realm']; allowed(realm)
        scope = 'repository:kunpeng-ai/' + name + ':pull'
        params = {'scope': scope}
        if fields.get('service'):
            params['service'] = fields['service']
        auth, _ = fetch(realm + ('&' if '?' in realm else '?') + urllib.parse.urlencode(params))
        token = auth.get('token') or auth.get('access_token')
        if not isinstance(token, str) or not token:
            raise ValueError('Anonymous metadata token unavailable')
        value, tag_digest = fetch(url, token)
    result = {'image': HOST + '/kunpeng-ai/' + name + ':latest',
              'tagManifestDigest': tag_digest, 'architectures': []}
    arm_digest = tag_digest
    if isinstance(value.get('manifests'), list):
        choices = []
        for row in value['manifests']:
            p = row.get('platform', {})
            result['architectures'].append(p)
            if p.get('os') == 'linux' and p.get('architecture') == 'arm64':
                choices.append(row)
        if len(choices) != 1:
            return dict(result, status='ARM64_NOT_UNIQUELY_AVAILABLE', arm64Candidates=len(choices))
        arm_digest = choices[0]['digest']
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', arm_digest):
            raise ValueError('Invalid architecture manifest identity')
        value, observed = fetch(prefix + '/manifests/' + arm_digest, token)
        if observed != arm_digest:
            raise ValueError('Architecture manifest content differs')
    config = value.get('config', {})
    config_digest = config.get('digest', '')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', config_digest) or not 0 < config.get('size', 0) <= 2 * 1024 * 1024:
        raise ValueError('Unsupported image manifest/config size')
    # Config is bounded JSON metadata, never a filesystem layer blob.
    configuration, observed = fetch(prefix + '/blobs/' + config_digest, token)
    if observed != config_digest:
        raise ValueError('Config metadata content differs')
    layers = value.get('layers')
    if not isinstance(layers, list) or len(layers) > 256:
        raise ValueError('Unsupported image layer metadata')
    selected = []
    for row in layers:
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', row.get('digest', '')) or type(row.get('size')) is not int or row['size'] < 0:
            raise ValueError('Invalid layer descriptor')
        selected.append({'digest': row['digest'], 'compressedBytes': row['size'], 'mediaType': row.get('mediaType')})
    arch = configuration.get('architecture'); system = configuration.get('os')
    return dict(result, status='ARM64_METADATA_READY' if (arch, system) == ('arm64', 'linux') else 'IMAGE_NOT_LINUX_ARM64',
                arm64ManifestDigest=arm_digest, architecture=arch, os=system,
                layers=selected, compressedLayerBytes=sum(r['compressedBytes'] for r in selected),
                storedOverlaybdBytes=None, hostExt4ContainerBytes=None,
                taskFilesAndPythonDependencies='NOT_INSPECTED_REQUIRES_IMAGE_PREPARATION')


def text(path):
    try:
        return Path(path).read_text()[:4096].strip()
    except OSError as error:
        return {'unavailable': type(error).__name__}


def main():
    if os.getuid() != os.geteuid() or platform.node() not in ('server1', 'agent1'):
        raise SystemExit('STOP: unexpected node or mixed user identity')
    memory = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        key = line.split(':', 1)[0]
        if key in ('MemTotal', 'MemAvailable', 'Cached', 'Buffers', 'SwapTotal', 'SwapFree'):
            memory[key] = int(line.split()[1]) * 1024
    disk = shutil.disk_usage('/home/jwk/agent')
    report = {'revision': 'dsbench-admission-v1', 'stage': 'P1_METADATA_ONLY',
              'hostname': platform.node(), 'uid': os.getuid(), 'kernel': platform.release(),
              'bootId': text('/proc/sys/kernel/random/boot_id'),
              'memoryBytes': memory, 'workspaceDiskBytes': {'total': disk.total, 'free': disk.free},
              'obmmPmemEnabled': text('/sys/module/obmm/parameters/pmem_ro_enable'),
              'devices': {}, 'images': [], 'SDK_called': False, 'Guest_created': False,
              'imageLayersDownloaded': False, 'servicesChanged': False,
              'UB_budget': 'UNCONFIRMED; no allocation or SDK query',
              'rootMigrationComplete': 'NOT_ATTESTED; entry installed does not prove all old artifacts migrated'}
    for name in ('/dev/kvm', '/dev/ublk-control', '/dev/obmm_pmem'):
        try:
            s = Path(name).stat()
            report['devices'][name] = {'character': stat.S_ISCHR(s.st_mode), 'mode': oct(stat.S_IMODE(s.st_mode)), 'uid': s.st_uid, 'gid': s.st_gid}
        except OSError as error:
            report['devices'][name] = {'unavailable': type(error).__name__}
    for name in NAMES:
        try:
            row = manifest(name)
        except urllib.error.HTTPError as error:
            row = {'image': name, 'status': 'REGISTRY_METADATA_BLOCKED', 'httpStatus': error.code}
            error.close()
        except Exception as error:
            row = {'image': name, 'status': 'REGISTRY_METADATA_BLOCKED', 'errorType': type(error).__name__}
        report['images'].append(row)
    ready = sum(r['status'] == 'ARM64_METADATA_READY' for r in report['images'])
    report.update(status='ADMISSION_METADATA_COLLECTED', arm64Ready=ready,
                  next='Review metadata; prepare /task files and dependencies only after input/resource admission')
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
