"""Read-only export of completed Y lifecycle evidence through the existing relay."""
import base64
import gzip
import hashlib
import io
import json
import os
import platform
import runpy
import shutil
import stat
import subprocess
import tarfile
from pathlib import Path

ROOT = Path('/home/jwk/aenv-memory-cause-20261120-Y')
HOME = Path('/home/jwk/aenv-y-clean-20261111')
ENTRY = Path('/home/jwk/y-aenv-control/relay-debian-clean-20261111/entry.py')
CREDENTIALS = ENTRY.with_name('credentials.json')
REPO = 'LittleFish-15/AgentENV-relay-results'
REPO_ID = 1438089386
PREFIX = 'root-large-artifacts-v1/y-debian-clean-20261111-v1/node-y/aenv-cause-20261120'
MAX_ARCHIVE = 64 * 1024**2
MAX_UNPACKED = 256 * 1024**2
MAX_TAIL = 32 * 1024**2


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_stable(path, start=0, limit=None):
    """Do not follow a final symlink or accept a changing file snapshot."""
    if path.is_symlink():
        raise RuntimeError('Symlink input refused: ' + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeError('Nonregular input refused: ' + str(path))
        if start < 0 or start > before.st_size:
            raise RuntimeError('Invalid input offset: ' + str(path))
        size = before.st_size - start if limit is None else min(limit, before.st_size - start)
        if size > MAX_UNPACKED:
            raise RuntimeError('Input exceeds unpacked budget: ' + str(path))
        stream.seek(start)
        raw = stream.read(size)
        after = os.fstat(stream.fileno())
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns')
        if len(raw) != size or any(getattr(before, k) != getattr(after, k) for k in fields):
            raise RuntimeError('Input changed during collection: ' + str(path))
    return raw, before


def main():
    if os.getuid() != 0 or os.geteuid() != 0 or platform.machine() != 'x86_64':
        raise RuntimeError('Expected the original Y root entry on x86_64')
    if ROOT.resolve(strict=True) != ROOT or HOME.resolve(strict=True) != HOME:
        raise RuntimeError('Experiment/home path redirected')
    os.setpriority(os.PRIO_PROCESS, 0, max(15, os.getpriority(os.PRIO_PROCESS, 0)))
    allowed = os.sched_getaffinity(0)
    os.sched_setaffinity(0, {max(allowed)})
    ionice = shutil.which('ionice')
    io_priority = None
    if ionice:
        io_priority = subprocess.run([ionice, '-c', '3', '-p', str(os.getpid())],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     timeout=5).returncode
    completed_raw, _ = read_stable(ROOT / 'experiment-result.json')
    if json.loads(completed_raw).get('success') is not True:
        raise RuntimeError('Completed successful experiment is required')
    api_key, _ = read_stable(HOME / 'config/api-key', limit=8192)
    api_key = api_key.strip()
    if not api_key:
        raise RuntimeError('API key unavailable for logfile redaction')
    paths = [ROOT / 'lifecycle/formal/operations.jsonl',
             ROOT / 'lifecycle/diagnostic/operations.jsonl', ROOT / 'lifecycle-journal.log']
    capture = ROOT / 'lifecycle/capture'
    if not capture.is_dir() or capture.is_symlink():
        raise RuntimeError('Capture directory unavailable or redirected')
    for path in sorted(capture.rglob('*')):
        if path.is_symlink():
            raise RuntimeError('Symlink in capture directory: ' + str(path))
        if path.is_file():
            paths.append(path)
        elif not path.is_dir():
            raise RuntimeError('Nonregular capture artifact: ' + str(path))
    if any(not p.is_file() for p in paths):
        raise RuntimeError('Required original file missing')
    total = sum(p.stat().st_size for p in paths)
    if total + min((HOME / 'logs/server.log').stat().st_size, MAX_TAIL) > MAX_UNPACKED:
        raise RuntimeError('Complete evidence exceeds256MiB; no files truncated')
    manifest = {'schema': 1, 'readOnly': True, 'experimentRoot': str(ROOT),
                'completedResultSha256': sha(completed_raw), 'priority': {
                    'nice': os.getpriority(os.PRIO_PROCESS, 0), 'cpu': max(allowed),
                    'ioniceIdleReturncode': io_priority}, 'files': [],
                'archiveLimitBytes': MAX_ARCHIVE, 'unpackedLimitBytes': MAX_UNPACKED}
    buffer = io.BytesIO()
    unpacked = 0
    with gzip.GzipFile(fileobj=buffer, mode='wb', filename='', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w|') as archive:
            def add(path, rel, raw, st, extra=None):
                nonlocal unpacked
                original_sha = sha(raw)
                replacements = raw.count(api_key)
                if replacements:
                    raw = raw.replace(api_key, b'[API_KEY_REDACTED]')
                    suffix = Path(rel).suffix
                    rel = rel[:-len(suffix)] + '.redacted' + suffix if suffix else rel + '.redacted'
                unpacked += len(raw)
                if unpacked > MAX_UNPACKED:
                    raise RuntimeError('Evidence exceeds256MiB after serialization')
                info = tarfile.TarInfo(rel)
                info.size = len(raw); info.mode = 0o600; info.mtime = int(st.st_mtime)
                archive.addfile(info, io.BytesIO(raw))
                manifest['files'].append({'source': str(path), 'archivePath': rel,
                    'sourceBytes': st.st_size, 'bytes': len(raw), 'mtimeNs': st.st_mtime_ns,
                    'inode': st.st_ino, 'originalFragmentSha256': original_sha,
                    'sha256': sha(raw), 'redactionCount': replacements, **(extra or {})})
                if buffer.tell() > MAX_ARCHIVE:
                    raise RuntimeError('Archive exceeds64MiB; export refused')
            for path in paths:
                if not path.resolve(strict=True).is_relative_to(ROOT):
                    raise RuntimeError('Artifact escaped experiment root')
                raw, st = read_stable(path)
                add(path, path.relative_to(ROOT).as_posix(), raw, st)
            logfile = HOME / 'logs/server.log'
            size = logfile.stat().st_size
            offset = max(0, size - MAX_TAIL)
            fragment, st = read_stable(logfile, offset, MAX_TAIL)
            # A tail may start in the middle of a credential-bearing line.
            discarded = 0
            if offset:
                end = fragment.find(b'\n')
                discarded = end + 1 if end >= 0 else len(fragment)
                fragment = fragment[discarded:]
                offset += discarded
            add(logfile, 'server-log-tail.log', fragment, st, {
                'offset': offset, 'sourceTotalBytes': st.st_size,
                'tailLimitBytes': MAX_TAIL, 'leadingPartialLineDiscardedBytes': discarded,
                'fragmentScope': 'Last at most32MiB; first partial line discarded when needed'})
            manifest['sourceFileCount'] = len(manifest['files'])
            manifest['fileCount'] = len(manifest['files']) + 1  # includes manifest.json
            manifest['unpackedDataBytes'] = unpacked
            metadata = (json.dumps(manifest, sort_keys=True, ensure_ascii=False, indent=2) + '\n').encode()
            if unpacked + len(metadata) > MAX_UNPACKED:
                raise RuntimeError('Evidence plus manifest exceeds256MiB')
            info = tarfile.TarInfo('manifest.json');info.size = len(metadata);info.mode = 0o600
            archive.addfile(info, io.BytesIO(metadata))
    packed = buffer.getvalue()
    if len(packed) > MAX_ARCHIVE:
        raise RuntimeError('Archive exceeds64MiB; no truncated archive uploaded')
    archive_sha = sha(packed)
    git_blob_sha = hashlib.sha1(b'blob ' + str(len(packed)).encode() + b'\0' + packed).hexdigest()
    local_archive = Path.cwd() / ('supplement-' + archive_sha + '.tgz')
    if local_archive.exists():
        if sha(local_archive.read_bytes()) != archive_sha:
            raise RuntimeError('Existing local artifact differs; preserved')
    else:
        with local_archive.open('xb') as stream:
            os.chmod(local_archive, 0o600);stream.write(packed)
    transport = runpy.run_path(str(ENTRY), run_name='supplement_transport')
    cst = CREDENTIALS.stat()
    if CREDENTIALS.is_symlink() or cst.st_uid != 0 or cst.st_mode & 0o077 or cst.st_size > 8192:
        raise RuntimeError('Unexpected relay credential owner/type/permissions')
    credentials = json.loads(read_stable(CREDENTIALS, limit=8192)[0])
    client = transport['API'].GitHub(credentials['resultToken'])
    client.private_repo(REPO, REPO_ID)
    repo = '/repos/' + REPO
    def api(method, path, value=None, allowed=(200, 201)):
        code, result, _ = client.request(method, repo + path, value)
        if code not in allowed:
            raise RuntimeError(method + ' ' + path + ' HTTP ' + str(code))
        return code, result
    _, blob = api('POST', '/git/blobs', {'encoding': 'base64',
                                       'content': base64.b64encode(packed).decode()})
    if blob.get('sha') != git_blob_sha:
        raise RuntimeError('Git blobSHA1 differs from original archive bytes')
    target = PREFIX + '/' + archive_sha + '.tgz'
    tree_cache = {}
    def existing_blob(tree_sha):
        parts = target.split('/')
        for i, component in enumerate(parts):
            if tree_sha not in tree_cache:
                _, tree_cache[tree_sha] = api('GET', '/git/trees/' + tree_sha)
            entry = next((r for r in tree_cache[tree_sha]['tree'] if r['path'] == component), None)
            if entry is None:
                return None
            if i == len(parts) - 1:
                if entry['type'] != 'blob':
                    raise RuntimeError('Artifact path exists as a different Git object type')
                return entry['sha']
            if entry['type'] != 'tree':
                raise RuntimeError('Artifact parent path is not a Git tree')
            tree_sha = entry['sha']
    committed = None
    for _ in range(3):
        _, ref = api('GET', '/git/ref/heads/main')
        head = ref['object']['sha']
        _, parent = api('GET', '/git/commits/' + head)
        found = existing_blob(parent['tree']['sha'])
        if found is not None:
            if found != git_blob_sha:
                raise RuntimeError('Existing checksum-named artifact has different bytes; preserved')
            committed = head;break
        _, tree = api('POST', '/git/trees', {'base_tree': parent['tree']['sha'], 'tree': [{
            'path': target, 'mode': '100644', 'type': 'blob', 'sha': git_blob_sha}]})
        _, commit = api('POST', '/git/commits', {'message': 'Y only: read-only original lifecycle evidence supplement',
                                              'tree': tree['sha'], 'parents': [head]})
        _, current = api('GET', '/git/ref/heads/main')
        if current['object']['sha'] != head:
            continue
        code, _ = api('PATCH', '/git/refs/heads/main', {'sha': commit['sha'], 'force': False},
                      allowed=(200, 409, 422))
        if code == 200:
            committed = commit['sha'];break
    if committed is None:
        raise RuntimeError('Concurrent result ref updates prevented commit after3attempts; no force push')
    print(json.dumps({'success': True, 'archiveBlobSha': git_blob_sha, 'archiveSha256': archive_sha,
        'archiveBytes': len(packed), 'commit': committed, 'path': target,
        'fileCount': manifest['fileCount'], 'sourceFileCount': manifest['sourceFileCount'],
        'unpackedDataBytes': unpacked, 'archiveUnpackedBytes': unpacked + len(metadata),
        'manifestPathInArchive': 'manifest.json', 'manifestSha256': sha(metadata),
        'redactionCount': sum(r['redactionCount'] for r in manifest['files']),
        'serverLogFragment': next(r for r in manifest['files'] if r['source'] == str(logfile)),
        'readOnly': True, 'localArchive': str(local_archive)}, separators=(',', ':')), flush=True)


if __name__ == '__main__':
    main()
