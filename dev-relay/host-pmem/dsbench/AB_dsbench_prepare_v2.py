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
AUTH_CACHE = {}
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


def allowed(url, storage=False):
    u = urllib.parse.urlparse(url)
    origin_ok = u.hostname == HOST or (storage and bool(u.hostname) and u.hostname.endswith('.obs.cn-north-4.myhuaweicloud.com'))
    if u.scheme != 'https' or not origin_ok or u.username or u.password or u.port not in (None, 443):
        raise ValueError('Registry/auth URL outside the reviewed anonymous origin')


class Redirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, storage=False):
        self.storage = storage

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        allowed(newurl, self.storage)
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None and urllib.parse.urlparse(newurl).hostname != urllib.parse.urlparse(req.full_url).hostname:
            redirected.remove_header('Authorization')
        return redirected


def fetch(url, token=None, storage=False):
    allowed(url)
    headers = {'Accept': ACCEPT, 'User-Agent': 'AgentENV-DSBench-admission-v1'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    with urllib.request.build_opener(Redirect(storage)).open(
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
    AUTH_CACHE[name] = token
    config = value.get('config', {})
    config_digest = config.get('digest', '')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', config_digest) or not 0 < config.get('size', 0) <= 2 * 1024 * 1024:
        raise ValueError('Unsupported image manifest/config size')
    # Config is bounded JSON metadata, never a filesystem layer blob.
    configuration, observed = fetch(prefix + '/blobs/' + config_digest, token, storage=True)
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


def owned_directory(path):
    root = Path('/home/jwk/agent')
    if not path.is_relative_to(root) or path.resolve() != path:
        raise ValueError('Preparation path escaped or redirected')
    if not path.exists():
        owned_directory(path.parent)
        path.mkdir(mode=0o700)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 1204 or info.st_mode & 0o022:
        raise ValueError('Preparation directory owner/type differs')


def blob_download(image, layer, cache):
    digest = layer['digest']; size = layer['compressedBytes']
    target = cache / digest[7:]

    def observed(path):
        if path.resolve() != path:
            raise ValueError('Blob path redirected')
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 1204 or info.st_size > size:
            raise ValueError('Existing blob metadata differs; preserved')
        h = hashlib.sha256()
        with path.open('rb') as stream:
            for part in iter(lambda: stream.read(1024 * 1024), b''):
                h.update(part)
        return info.st_size, 'sha256:' + h.hexdigest()

    def promote(part):
        count, actual = observed(part)
        if count != size or actual != digest:
            return False
        os.link(part, target)
        part.unlink()  # Only a verified temporary hardlink in this experiment.
        print('BLOB_READY=' + digest[7:19], flush=True)
        return True

    if target.exists():
        count, actual = observed(target)
        if count != size or actual != digest:
            raise ValueError('Existing final blob differs; preserved')
        return target
    name = image['image'].split('/')[2].split(':')[0]
    token = AUTH_CACHE[name]
    url = 'https://' + HOST + '/v2/kunpeng-ai/' + name + '/blobs/' + digest
    opener = urllib.request.build_opener(Redirect(storage=True))
    # Retain the original partial on corruption or ignored Range. At most one
    # additional fixed retry file; repeating a task cannot grow new filenames.
    for part in (target.with_suffix('.partial'), target.with_suffix('.retry-v2.partial')):
        if part.is_symlink():
            raise ValueError('Partial blob redirected')
        if part.exists() and promote(part):
            return target
        if part.exists() and part.stat().st_size == size:
            count, actual = observed(part)
            print('BLOB_EXISTING_PARTIAL=' + json.dumps({'digest': digest, 'bytes': count,
                  'observedSha256': actual, 'expectedBytes': size}), flush=True)
            continue
        for attempt in range(2):
            if part.exists():
                count, actual = observed(part)
            else:
                count, actual = 0, None
            if shutil.disk_usage(cache).free < size - count + 1024**3:
                raise ValueError('Insufficient workspace for bounded resume')
            headers = {'User-Agent': 'AgentENV-DSBench-prepare-v2', 'Accept-Encoding': 'identity'}
            if token:
                headers['Authorization'] = 'Bearer ' + token
            if count:
                headers['Range'] = 'bytes=' + str(count) + '-'
            initial = count
            try:
                with opener.open(urllib.request.Request(url, headers=headers), timeout=30) as response:
                    status = response.status
                    content_range = response.headers.get('Content-Range')
                    detail = {'digest': digest, 'resumeOffset': initial, 'attempt': attempt + 1,
                              'httpStatus': status, 'contentLength': response.headers.get('Content-Length'),
                              'contentRange': content_range, 'expectedBytes': size}
                    print('BLOB_RESPONSE=' + json.dumps(detail), flush=True)
                    if response.headers.get('Content-Encoding', 'identity') != 'identity':
                        raise ValueError('Encoded blob transport refused')
                    if count and status == 200:
                        # Never append a complete HTTP200 body to an existing prefix.
                        break
                    if status == 206:
                        match = re.fullmatch(r'bytes (\d+)-(\d+)/(\d+)', content_range or '')
                        if not match or tuple(map(int, match.groups()))[0] != count or int(match[3]) != size or not count <= int(match[2]) < size:
                            raise ValueError('Invalid Range response; partial preserved')
                    elif status != 200 or count:
                        raise ValueError('Unexpected blob response; partial preserved')
                    with part.open('ab' if part.exists() else 'xb') as stream:
                        while True:
                            data = response.read(min(1024 * 1024, size - count + 1))
                            if not data:
                                break
                            count += len(data)
                            if count > size:
                                raise ValueError('Layer exceeds declared size; partial preserved')
                            stream.write(data)
                        stream.flush(); os.fsync(stream.fileno())
                if promote(part):
                    return target
                count, actual = observed(part)
                print('BLOB_INCOMPLETE=' + json.dumps({'digest': digest, 'bytes': count,
                      'observedSha256': actual, 'expectedBytes': size}), flush=True)
                if count == size:
                    break
            except Exception as error:
                print('BLOB_TRANSFER_ERROR=' + json.dumps({'digest': digest,
                      'errorType': type(error).__name__, 'partialPreserved': True}), flush=True)
                if isinstance(error, ValueError):
                    break
    raise ValueError('Bounded resume incomplete; known partials preserved for review')


def layer_inventory(path):
    import tarfile
    from pathlib import PurePosixPath
    events = []; apparent = 0; members = 0
    with tarfile.open(path, mode='r|gz') as archive:
        for item in archive:
            members += 1; apparent += item.size
            if members > 500000 or apparent > 16 * 1024**3:
                raise ValueError('Layer archive exceeds reviewed scan bounds')
            name = item.name
            while name.startswith('./'):
                name = name[2:]
            p = PurePosixPath(name)
            if p.is_absolute() or '..' in p.parts:
                raise ValueError('Noncanonical archive member; not extracted')
            parent, leaf = str(p.parent), p.name
            if leaf.startswith('.wh.'):
                events.append({'kind': 'whiteout', 'parent': parent, 'leaf': leaf})
                continue
            package = None
            if '/site-packages/' in name or '/dist-packages/' in name:
                for candidate in ('pandas', 'numpy', 'sklearn', 'scipy', 'openpyxl'):
                    if ('/' + candidate + '/') in name:
                        package = candidate
                        break
            interpreter = name in ('usr/bin/python', 'usr/bin/python3', 'usr/local/bin/python', 'usr/local/bin/python3')
            if name.startswith('task/') or package or interpreter:
                if len(events) >= 50000:
                    raise ValueError('Selected metadata exceeds bounds')
                events.append({'kind': 'entry', 'path': name, 'bytes': item.size,
                               'regular': item.isfile(), 'directory': item.isdir(),
                               'link': item.issym() or item.islnk(), 'package': package,
                               'interpreter': interpreter})
    return {'events': events, 'apparentMemberBytes': apparent, 'members': members}


def apply_events(state, events):
    # Whiteouts hide lower-layer entries, never newly added entries of this layer.
    for item in events:
        if item['kind'] == 'entry':
            continue
        parent = item['parent']; leaf = item['leaf']
        if leaf == '.wh..wh..opq':
            prefix = '' if parent == '.' else parent + '/'
            for key in list(state):
                if key.startswith(prefix):
                    del state[key]
        else:
            victim = ('' if parent == '.' else parent + '/') + leaf[4:]
            for key in list(state):
                if key == victim or key.startswith(victim + '/'):
                    del state[key]
    for item in events:
        if item['kind'] == 'entry':
            state[item['path']] = item


def prepare():
    report = main()
    report['revision'] = 'dsbench-prepare-v2'
    report['preparation'] = {'state': 'NOT_STARTED', 'SDK_called': False,
                              'imageProgramsExecuted': False, 'layersExtractedToHostRootfs': False}
    try:
        expected = {r['image']: r for r in PINNED}
        actual = {r['image']: r for r in report['images'] if r['status'] == 'ARM64_METADATA_READY'}
        if set(actual) != set(expected):
            raise ValueError('Registry admission incomplete; no layers downloaded')
        for image, pinned in expected.items():
            if actual[image]['arm64ManifestDigest'] != pinned['arm64ManifestDigest'] or actual[image]['layers'] != pinned['layers']:
                raise ValueError('Image tag changed since reviewed metadata; no layers downloaded')
        unique = {layer['digest']: layer['compressedBytes'] for image in PINNED for layer in image['layers']}
        if sum(unique.values()) > 1024**3:
            raise ValueError('Deduplicated compressed layer budget exceeds 1GiB')
        if os.geteuid() == 0:
            # Only drop authority; no supplementary group or capability grant.
            os.setgroups([]); os.setgid(1205); os.setuid(1204)
        if os.getuid() != os.geteuid() or os.getuid() != 1204 or os.getgid() != 1205:
            raise ValueError('Preparation must run as jwk')
        os.umask(0o077)
        root = Path('/home/jwk/agent/dsbench-20261031')
        owned_directory(root); cache = root / 'oci-blobs'; owned_directory(cache)
        os.chdir(root)
        scans = {}; outputs = []
        for image in PINNED:
            state = {}
            for layer in image['layers']:
                path = blob_download(image, layer, cache)
                if layer['digest'] not in scans:
                    scans[layer['digest']] = layer_inventory(path)
                apply_events(state, scans[layer['digest']]['events'])
            task = [v for k, v in state.items() if k.startswith('task/') and not v['directory']]
            outputs.append({'image': image['image'], 'arm64ManifestDigest': image['arm64ManifestDigest'],
                            'taskFiles': task, 'packageTreesPresent': sorted({v['package'] for v in state.values() if v.get('package')}),
                            'interpreterEntries': [v for v in state.values() if v.get('interpreter')],
                            'runtimeDependenciesVerifiedByExecution': False})
        value = {'version': 1, 'state': 'COMPRESSED_OCI_INPUTS_PREPARED_NOT_EXECUTED',
                 'uid': os.getuid(), 'uniqueCompressedBytes': sum(unique.values()),
                 'images': outputs, 'sourceManifests': PINNED}
        target = root / 'prepared-inputs.json'
        raw = json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2).encode()
        if target.exists():
            if target.is_symlink() or target.read_bytes() != raw:
                raise ValueError('Existing prepared input record differs; preserved')
        else:
            with target.open('xb') as stream:
                stream.write(raw)
        report['preparation'] = {**value, 'recordPath': str(target), 'blobDirectory': str(cache),
                                  'imageProgramsExecuted': False, 'SDK_called': False}
    except Exception as error:
        report['preparation'].update(state='PREPARATION_STOPPED_PRESERVE_FILES', errorType=type(error).__name__)
        if type(error) is ValueError:
            report['preparation']['reason'] = str(error)
    print('BEGIN_DSBENCH_PREPARATION_REPORT', flush=True)
    print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)
    print('END_DSBENCH_PREPARATION_REPORT', flush=True)


def main():
    if os.getuid() != os.geteuid() or platform.node() not in ('server1', 'agent1'):
        raise SystemExit('STOP: unexpected node or mixed user identity')
    memory = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        key = line.split(':', 1)[0]
        if key in ('MemTotal', 'MemAvailable', 'Cached', 'Buffers', 'SwapTotal', 'SwapFree'):
            memory[key] = int(line.split()[1]) * 1024
    disk = shutil.disk_usage('/home/jwk/agent')
    report = {'revision': 'dsbench-admission-v2', 'stage': 'P1_METADATA_ONLY',
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
            if type(error) is ValueError and str(error).startswith(('Registry/', 'Registry metadata', 'Anonymous metadata', 'Unsupported image', 'Unsupported image layer', 'Invalid architecture', 'Architecture manifest', 'Config metadata', 'Invalid layer')):
                row['reason'] = str(error)
        report['images'].append(row)
    ready = sum(r['status'] == 'ARM64_METADATA_READY' for r in report['images'])
    report.update(status='ADMISSION_METADATA_COLLECTED', arm64Ready=ready,
                  next='Review metadata; prepare /task files and dependencies only after input/resource admission')
    return report




PINNED = [{'image': 'swr.cn-north-4.myhuaweicloud.com/kunpeng-ai/dsbench-analysis-00000001-2016-round-1-section-2-chip-off-the-old-block:latest', 'tagManifestDigest': 'sha256:e2997325d2ba7a6b59fcba276477b88022245001161efc0a651c79e1bf20f566', 'architectures': [], 'status': 'ARM64_METADATA_READY', 'arm64ManifestDigest': 'sha256:e2997325d2ba7a6b59fcba276477b88022245001161efc0a651c79e1bf20f566', 'architecture': 'arm64', 'os': 'linux', 'layers': [{'digest': 'sha256:7cdd1ba5135a6d8409fbcfc8c18a42bb7a94478a8c5e2039232b1ecfeb53b1a2', 'compressedBytes': 31437713, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:79f4d98c31c2d8174aa8768b7d419a89cf8d082b14fb415c204d4b03229fbdbc', 'compressedBytes': 1275258, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:11ac7ae14ecdc34224ee2852890f802ebc8efd8fae275a29cb2cb11127d26ae0', 'compressedBytes': 13872468, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:e438e1ba382f38ea04488b457dd14dd5fdfbfc62f3c40058d42f4442f08ead9a', 'compressedBytes': 250, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:d8a54164489afe2e2b9112bbbc87d3f6382b993d9dc8e5e4d862e05db7c12379', 'compressedBytes': 42424064, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:63bdcdf07fb3f9bc9c8c5b4354cfdab542831616a06cf70de0ae42208b7fd27e', 'compressedBytes': 93, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:367afce182a3b9177dddb33696a78d98bf6247203ba26f74401ee843d131790c', 'compressedBytes': 113290, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:9bcd819494ae128eef59aff7aa696cb16e444066ae17cc786ff0a9200d034bc0', 'compressedBytes': 2016, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}], 'compressedLayerBytes': 89125152, 'storedOverlaybdBytes': None, 'hostExt4ContainerBytes': None, 'taskFilesAndPythonDependencies': 'NOT_INSPECTED_REQUIRES_IMAGE_PREPARATION'}, {'image': 'swr.cn-north-4.myhuaweicloud.com/kunpeng-ai/dsbench-analysis-00000005-2016-round-1-section-3-roll-the-dice:latest', 'tagManifestDigest': 'sha256:9b16827a4072e36958b1847be41fd31b924f6dd785285b41f9b6e06d9f059e25', 'architectures': [], 'status': 'ARM64_METADATA_READY', 'arm64ManifestDigest': 'sha256:9b16827a4072e36958b1847be41fd31b924f6dd785285b41f9b6e06d9f059e25', 'architecture': 'arm64', 'os': 'linux', 'layers': [{'digest': 'sha256:7cdd1ba5135a6d8409fbcfc8c18a42bb7a94478a8c5e2039232b1ecfeb53b1a2', 'compressedBytes': 31437713, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:79f4d98c31c2d8174aa8768b7d419a89cf8d082b14fb415c204d4b03229fbdbc', 'compressedBytes': 1275258, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:11ac7ae14ecdc34224ee2852890f802ebc8efd8fae275a29cb2cb11127d26ae0', 'compressedBytes': 13872468, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:e438e1ba382f38ea04488b457dd14dd5fdfbfc62f3c40058d42f4442f08ead9a', 'compressedBytes': 250, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:d8a54164489afe2e2b9112bbbc87d3f6382b993d9dc8e5e4d862e05db7c12379', 'compressedBytes': 42424064, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:63bdcdf07fb3f9bc9c8c5b4354cfdab542831616a06cf70de0ae42208b7fd27e', 'compressedBytes': 93, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:a1ee4ff149dd105542285b0ee9afb1b491ab64052fa546fa34bef245a581ae86', 'compressedBytes': 335801, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:b10194d74dc68eee0589147ab78fc55e1b7ea8e193f7fa9babc3b11f68251d48', 'compressedBytes': 2001, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}], 'compressedLayerBytes': 89347648, 'storedOverlaybdBytes': None, 'hostExt4ContainerBytes': None, 'taskFilesAndPythonDependencies': 'NOT_INSPECTED_REQUIRES_IMAGE_PREPARATION'}, {'image': 'swr.cn-north-4.myhuaweicloud.com/kunpeng-ai/dsbench-analysis-00000011-2014-round-2-purple-city:latest', 'tagManifestDigest': 'sha256:fc8bfe8dae7e9b28a923e257b2969374e467fd0ea803b2a0c482b3764f5d4d93', 'architectures': [], 'status': 'ARM64_METADATA_READY', 'arm64ManifestDigest': 'sha256:fc8bfe8dae7e9b28a923e257b2969374e467fd0ea803b2a0c482b3764f5d4d93', 'architecture': 'arm64', 'os': 'linux', 'layers': [{'digest': 'sha256:7cdd1ba5135a6d8409fbcfc8c18a42bb7a94478a8c5e2039232b1ecfeb53b1a2', 'compressedBytes': 31437713, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:79f4d98c31c2d8174aa8768b7d419a89cf8d082b14fb415c204d4b03229fbdbc', 'compressedBytes': 1275258, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:11ac7ae14ecdc34224ee2852890f802ebc8efd8fae275a29cb2cb11127d26ae0', 'compressedBytes': 13872468, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:e438e1ba382f38ea04488b457dd14dd5fdfbfc62f3c40058d42f4442f08ead9a', 'compressedBytes': 250, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:d8a54164489afe2e2b9112bbbc87d3f6382b993d9dc8e5e4d862e05db7c12379', 'compressedBytes': 42424064, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:63bdcdf07fb3f9bc9c8c5b4354cfdab542831616a06cf70de0ae42208b7fd27e', 'compressedBytes': 93, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:82cd27990198e6bece14458287fbd05fac105e728d1baec5bba2887478784707', 'compressedBytes': 76233, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:fd63e59086bb580990124a5cb13ea74bb36ea399e84a66c165dc96155c88e31f', 'compressedBytes': 1969, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}], 'compressedLayerBytes': 89088048, 'storedOverlaybdBytes': None, 'hostExt4ContainerBytes': None, 'taskFilesAndPythonDependencies': 'NOT_INSPECTED_REQUIRES_IMAGE_PREPARATION'}, {'image': 'swr.cn-north-4.myhuaweicloud.com/kunpeng-ai/dsbench-analysis-00000013-2017-round-2-late-again:latest', 'tagManifestDigest': 'sha256:8ab1b9561df0297060e7a154b14de4a8eca4eef4e1544e4457466c9e46ec4ba9', 'architectures': [], 'status': 'ARM64_METADATA_READY', 'arm64ManifestDigest': 'sha256:8ab1b9561df0297060e7a154b14de4a8eca4eef4e1544e4457466c9e46ec4ba9', 'architecture': 'arm64', 'os': 'linux', 'layers': [{'digest': 'sha256:7cdd1ba5135a6d8409fbcfc8c18a42bb7a94478a8c5e2039232b1ecfeb53b1a2', 'compressedBytes': 31437713, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:79f4d98c31c2d8174aa8768b7d419a89cf8d082b14fb415c204d4b03229fbdbc', 'compressedBytes': 1275258, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:11ac7ae14ecdc34224ee2852890f802ebc8efd8fae275a29cb2cb11127d26ae0', 'compressedBytes': 13872468, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:e438e1ba382f38ea04488b457dd14dd5fdfbfc62f3c40058d42f4442f08ead9a', 'compressedBytes': 250, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:d8a54164489afe2e2b9112bbbc87d3f6382b993d9dc8e5e4d862e05db7c12379', 'compressedBytes': 42424064, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:63bdcdf07fb3f9bc9c8c5b4354cfdab542831616a06cf70de0ae42208b7fd27e', 'compressedBytes': 93, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:51d5ecdca4787eac27a1f23b9835bd477c0562cfd978428e836d13500636bc30', 'compressedBytes': 470436, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:bb8743390f3b919a80124378ee13054b04d63af8321aa3793396eb4228a6dd9c', 'compressedBytes': 2000, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}], 'compressedLayerBytes': 89482282, 'storedOverlaybdBytes': None, 'hostExt4ContainerBytes': None, 'taskFilesAndPythonDependencies': 'NOT_INSPECTED_REQUIRES_IMAGE_PREPARATION'}, {'image': 'swr.cn-north-4.myhuaweicloud.com/kunpeng-ai/dsbench-analysis-00000028-2015-round-one-options-to-call:latest', 'tagManifestDigest': 'sha256:797b0c24958dfa74ae873425c7d793f2cbb55bb00703627ba2b9ff609fe25062', 'architectures': [], 'status': 'ARM64_METADATA_READY', 'arm64ManifestDigest': 'sha256:797b0c24958dfa74ae873425c7d793f2cbb55bb00703627ba2b9ff609fe25062', 'architecture': 'arm64', 'os': 'linux', 'layers': [{'digest': 'sha256:7cdd1ba5135a6d8409fbcfc8c18a42bb7a94478a8c5e2039232b1ecfeb53b1a2', 'compressedBytes': 31437713, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:79f4d98c31c2d8174aa8768b7d419a89cf8d082b14fb415c204d4b03229fbdbc', 'compressedBytes': 1275258, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:11ac7ae14ecdc34224ee2852890f802ebc8efd8fae275a29cb2cb11127d26ae0', 'compressedBytes': 13872468, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:e438e1ba382f38ea04488b457dd14dd5fdfbfc62f3c40058d42f4442f08ead9a', 'compressedBytes': 250, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:d8a54164489afe2e2b9112bbbc87d3f6382b993d9dc8e5e4d862e05db7c12379', 'compressedBytes': 42424064, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:63bdcdf07fb3f9bc9c8c5b4354cfdab542831616a06cf70de0ae42208b7fd27e', 'compressedBytes': 93, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:4ff35f8a4f7a8c7f88ba9ce9c4cfb6db6466ee1af9ef0ce7e274c78850cf8cde', 'compressedBytes': 140222, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:9e59967a93739528e43015fe0b93a99f74b30859a4fb49b9458e67244172a950', 'compressedBytes': 1989, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}], 'compressedLayerBytes': 89152057, 'storedOverlaybdBytes': None, 'hostExt4ContainerBytes': None, 'taskFilesAndPythonDependencies': 'NOT_INSPECTED_REQUIRES_IMAGE_PREPARATION'}, {'image': 'swr.cn-north-4.myhuaweicloud.com/kunpeng-ai/dsbench-modeling-bike-sharing-demand:latest', 'tagManifestDigest': 'sha256:7fb6ceb6e2eb2e5a8aa0f21d6c9daff37699f3a6bb812f53fa7c45283977a734', 'architectures': [], 'status': 'ARM64_METADATA_READY', 'arm64ManifestDigest': 'sha256:7fb6ceb6e2eb2e5a8aa0f21d6c9daff37699f3a6bb812f53fa7c45283977a734', 'architecture': 'arm64', 'os': 'linux', 'layers': [{'digest': 'sha256:7cdd1ba5135a6d8409fbcfc8c18a42bb7a94478a8c5e2039232b1ecfeb53b1a2', 'compressedBytes': 31437713, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:79f4d98c31c2d8174aa8768b7d419a89cf8d082b14fb415c204d4b03229fbdbc', 'compressedBytes': 1275258, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:11ac7ae14ecdc34224ee2852890f802ebc8efd8fae275a29cb2cb11127d26ae0', 'compressedBytes': 13872468, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:e438e1ba382f38ea04488b457dd14dd5fdfbfc62f3c40058d42f4442f08ead9a', 'compressedBytes': 250, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:4e6aa18d0749573bf58a407f1b718fe6f45b160bcf971d1a30af8e5bdb223c7d', 'compressedBytes': 431550, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:42c11a0b8d0bacbff8d63a05fb83617abf27e2eabf9b470c0fbe7413d8e5ce9b', 'compressedBytes': 301082874, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:86b18045607e03c6727ee2a604087ec5394680674194680a76099828ae8cb1a4', 'compressedBytes': 94, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:27b3b186b04a405b6168413dfb941d494c0ee47833afb7f37d0ccb6f0524b1cd', 'compressedBytes': 162554, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:9868ef36241fc2ec39af18ae86b0093120a754c7e517005c802b99ea072b734b', 'compressedBytes': 12104, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}], 'compressedLayerBytes': 348274865, 'storedOverlaybdBytes': None, 'hostExt4ContainerBytes': None, 'taskFilesAndPythonDependencies': 'NOT_INSPECTED_REQUIRES_IMAGE_PREPARATION'}, {'image': 'swr.cn-north-4.myhuaweicloud.com/kunpeng-ai/dsbench-modeling-nlp-getting-started:latest', 'tagManifestDigest': 'sha256:87cd51c5c6b19732c068a4bef5844ea3bdb939e1be70ed24820e54f125669a15', 'architectures': [], 'status': 'ARM64_METADATA_READY', 'arm64ManifestDigest': 'sha256:87cd51c5c6b19732c068a4bef5844ea3bdb939e1be70ed24820e54f125669a15', 'architecture': 'arm64', 'os': 'linux', 'layers': [{'digest': 'sha256:7cdd1ba5135a6d8409fbcfc8c18a42bb7a94478a8c5e2039232b1ecfeb53b1a2', 'compressedBytes': 31437713, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:79f4d98c31c2d8174aa8768b7d419a89cf8d082b14fb415c204d4b03229fbdbc', 'compressedBytes': 1275258, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:11ac7ae14ecdc34224ee2852890f802ebc8efd8fae275a29cb2cb11127d26ae0', 'compressedBytes': 13872468, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:e438e1ba382f38ea04488b457dd14dd5fdfbfc62f3c40058d42f4442f08ead9a', 'compressedBytes': 250, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:4e6aa18d0749573bf58a407f1b718fe6f45b160bcf971d1a30af8e5bdb223c7d', 'compressedBytes': 431550, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:42c11a0b8d0bacbff8d63a05fb83617abf27e2eabf9b470c0fbe7413d8e5ce9b', 'compressedBytes': 301082874, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:86b18045607e03c6727ee2a604087ec5394680674194680a76099828ae8cb1a4', 'compressedBytes': 94, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:c1c2164de417f6e8d6a46dd59ef874ff21891b0bc49d32120d866c3ed582614b', 'compressedBytes': 488895, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:4a9eb0590b1c727d0d6e492ef32bf10384c422de9b8518516ad1cdfa94395f59', 'compressedBytes': 5268, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}], 'compressedLayerBytes': 348594370, 'storedOverlaybdBytes': None, 'hostExt4ContainerBytes': None, 'taskFilesAndPythonDependencies': 'NOT_INSPECTED_REQUIRES_IMAGE_PREPARATION'}, {'image': 'swr.cn-north-4.myhuaweicloud.com/kunpeng-ai/dsbench-modeling-playground-series-s3e13:latest', 'tagManifestDigest': 'sha256:0ba4a79318aff785e717e3239e5e008e2893199d853923c4122266ce9f31c6c0', 'architectures': [], 'status': 'ARM64_METADATA_READY', 'arm64ManifestDigest': 'sha256:0ba4a79318aff785e717e3239e5e008e2893199d853923c4122266ce9f31c6c0', 'architecture': 'arm64', 'os': 'linux', 'layers': [{'digest': 'sha256:7cdd1ba5135a6d8409fbcfc8c18a42bb7a94478a8c5e2039232b1ecfeb53b1a2', 'compressedBytes': 31437713, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:79f4d98c31c2d8174aa8768b7d419a89cf8d082b14fb415c204d4b03229fbdbc', 'compressedBytes': 1275258, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:11ac7ae14ecdc34224ee2852890f802ebc8efd8fae275a29cb2cb11127d26ae0', 'compressedBytes': 13872468, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:e438e1ba382f38ea04488b457dd14dd5fdfbfc62f3c40058d42f4442f08ead9a', 'compressedBytes': 250, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:4e6aa18d0749573bf58a407f1b718fe6f45b160bcf971d1a30af8e5bdb223c7d', 'compressedBytes': 431550, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:42c11a0b8d0bacbff8d63a05fb83617abf27e2eabf9b470c0fbe7413d8e5ce9b', 'compressedBytes': 301082874, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:86b18045607e03c6727ee2a604087ec5394680674194680a76099828ae8cb1a4', 'compressedBytes': 94, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:091f0b8549bb5c2cdca1cf841faad9eb2380384fe189e9bb5c60dc83aebcaf3a', 'compressedBytes': 16454, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:a3d6b8a046b0fd4878c94bfc4efbc8890251f6608948416007002b8400fa6192', 'compressedBytes': 1633, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}], 'compressedLayerBytes': 348118294, 'storedOverlaybdBytes': None, 'hostExt4ContainerBytes': None, 'taskFilesAndPythonDependencies': 'NOT_INSPECTED_REQUIRES_IMAGE_PREPARATION'}, {'image': 'swr.cn-north-4.myhuaweicloud.com/kunpeng-ai/dsbench-modeling-spaceship-titanic:latest', 'tagManifestDigest': 'sha256:85de96853ff6a34e06a32a663dfdaf7f8bc6db33b35584a810270207e5714ebc', 'architectures': [], 'status': 'ARM64_METADATA_READY', 'arm64ManifestDigest': 'sha256:85de96853ff6a34e06a32a663dfdaf7f8bc6db33b35584a810270207e5714ebc', 'architecture': 'arm64', 'os': 'linux', 'layers': [{'digest': 'sha256:7cdd1ba5135a6d8409fbcfc8c18a42bb7a94478a8c5e2039232b1ecfeb53b1a2', 'compressedBytes': 31437713, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:79f4d98c31c2d8174aa8768b7d419a89cf8d082b14fb415c204d4b03229fbdbc', 'compressedBytes': 1275258, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:11ac7ae14ecdc34224ee2852890f802ebc8efd8fae275a29cb2cb11127d26ae0', 'compressedBytes': 13872468, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:e438e1ba382f38ea04488b457dd14dd5fdfbfc62f3c40058d42f4442f08ead9a', 'compressedBytes': 250, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:4e6aa18d0749573bf58a407f1b718fe6f45b160bcf971d1a30af8e5bdb223c7d', 'compressedBytes': 431550, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:42c11a0b8d0bacbff8d63a05fb83617abf27e2eabf9b470c0fbe7413d8e5ce9b', 'compressedBytes': 301082874, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:86b18045607e03c6727ee2a604087ec5394680674194680a76099828ae8cb1a4', 'compressedBytes': 94, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:8d13b138ab9b0e64f51fbec2d39aa0c9cfc81675d1b71642017fa5f90fc346bd', 'compressedBytes': 231165, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:874129b40c35bc899816965bd5e5bfed320baf61919619d8f37788d14546281b', 'compressedBytes': 6452, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}], 'compressedLayerBytes': 348337824, 'storedOverlaybdBytes': None, 'hostExt4ContainerBytes': None, 'taskFilesAndPythonDependencies': 'NOT_INSPECTED_REQUIRES_IMAGE_PREPARATION'}, {'image': 'swr.cn-north-4.myhuaweicloud.com/kunpeng-ai/dsbench-modeling-titanic:latest', 'tagManifestDigest': 'sha256:d287f235d83c213a5bedd22f7e2ff95b5d1e7c5fe7a570da82a53409447e1c1d', 'architectures': [], 'status': 'ARM64_METADATA_READY', 'arm64ManifestDigest': 'sha256:d287f235d83c213a5bedd22f7e2ff95b5d1e7c5fe7a570da82a53409447e1c1d', 'architecture': 'arm64', 'os': 'linux', 'layers': [{'digest': 'sha256:7cdd1ba5135a6d8409fbcfc8c18a42bb7a94478a8c5e2039232b1ecfeb53b1a2', 'compressedBytes': 31437713, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:79f4d98c31c2d8174aa8768b7d419a89cf8d082b14fb415c204d4b03229fbdbc', 'compressedBytes': 1275258, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:11ac7ae14ecdc34224ee2852890f802ebc8efd8fae275a29cb2cb11127d26ae0', 'compressedBytes': 13872468, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:e438e1ba382f38ea04488b457dd14dd5fdfbfc62f3c40058d42f4442f08ead9a', 'compressedBytes': 250, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:4e6aa18d0749573bf58a407f1b718fe6f45b160bcf971d1a30af8e5bdb223c7d', 'compressedBytes': 431550, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:42c11a0b8d0bacbff8d63a05fb83617abf27e2eabf9b470c0fbe7413d8e5ce9b', 'compressedBytes': 301082874, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:86b18045607e03c6727ee2a604087ec5394680674194680a76099828ae8cb1a4', 'compressedBytes': 94, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:83bca71e5b1d66c795e0063a0140ebcd7c4290237ad249c0bb63b3cdae25ce7d', 'compressedBytes': 26860, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}, {'digest': 'sha256:c111de86f60e07563a325ca039d76f885970ebe20af320566556b7e98510eb95', 'compressedBytes': 1193, 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'}], 'compressedLayerBytes': 348128260, 'storedOverlaybdBytes': None, 'hostExt4ContainerBytes': None, 'taskFilesAndPythonDependencies': 'NOT_INSPECTED_REQUIRES_IMAGE_PREPARATION'}]

if __name__ == '__main__':
    prepare()

