"""Upload the already-created Y evidence archive in bounded64KiB Git blobs."""
import base64
import hashlib
import json
import os
import platform
import re
import runpy
import shutil
import stat
import subprocess
import time
from pathlib import Path

STATE = Path('/home/jwk/y-aenv-control/relay-debian-clean-20261111')
SOURCE_JOB = STATE / 'jobs/y-aenv-memory-cause-20261120-supplement-node-y'
REPO = 'LittleFish-15/AgentENV-relay-results'
REPO_ID = 1438089386
PREFIX = 'root-large-artifacts-v1/y-debian-clean-20261111-v1/node-y/aenv-cause-20261120'
CHUNK = 64 * 1024
MAX_BYTES = 64 * 1024**2


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git_sha(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def save(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    tmp = path.with_name(path.name + '.next')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())
    os.replace(tmp, path)


def main():
    if os.getuid() != 0 or os.geteuid() != 0 or platform.machine() != 'x86_64':
        raise RuntimeError('Expected Y root entry on x86_64')
    os.setpriority(os.PRIO_PROCESS, 0, max(15, os.getpriority(os.PRIO_PROCESS, 0)))
    os.sched_setaffinity(0, {max(os.sched_getaffinity(0))})
    if shutil.which('ionice'):
        subprocess.run(['ionice', '-c', '3', '-p', str(os.getpid())], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=5)
    archives = list(SOURCE_JOB.glob('supplement-*.tgz'))
    if len(archives) != 1:
        raise RuntimeError('Expected precisely one existing supplement archive')
    archive = archives[0]
    match = re.fullmatch(r'supplement-([0-9a-f]{64})\.tgz', archive.name)
    if not match or archive.is_symlink() or archive.resolve(strict=True).parent != SOURCE_JOB:
        raise RuntimeError('Unexpected archive path or filename')
    fd = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_BYTES:
            raise RuntimeError('Archive is not a regular file within64MiB')
        raw = stream.read(MAX_BYTES + 1)
        after = os.fstat(stream.fileno())
    if len(raw) != before.st_size or any(getattr(before, k) != getattr(after, k)
            for k in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns')) or sha(raw) != match[1]:
        raise RuntimeError('Original archive changed or differs from filenameSHA256')
    archive_sha = match[1]
    prefix = PREFIX + '/chunks-' + archive_sha
    progress_name = 'upload-chunks-' + archive_sha + '.json'
    progress_path = Path.cwd() / progress_name
    chunks = []
    for i, offset in enumerate(range(0, len(raw), CHUNK)):
        data = raw[offset:offset + CHUNK]
        chunks.append({'index': i, 'blobSha': git_sha(data), 'bytes': len(data),
                       'sha256': sha(data), 'path': prefix + '/%04d.bin' % i})
    completed = {}
    for prior in (STATE / 'jobs').glob('y-aenv-memory-cause-20261120-*/' + progress_name):
        if prior.is_symlink() or not prior.is_file() or prior.stat().st_size > 1024**2:
            continue
        value = json.loads(prior.read_text())
        if value.get('archiveSha256') != archive_sha or value.get('chunkSize') != CHUNK:
            continue
        for row in value.get('uploadedChunks', []):
            index = row.get('index')
            if isinstance(index, int) and 0 <= index < len(chunks) and row == chunks[index]:
                completed[index] = row
    progress = {'archiveSha256': archive_sha, 'archiveBytes': len(raw), 'chunkSize': CHUNK,
                'sourceArchive': str(archive), 'uploadedChunks': [], 'state': 'uploading',
                'resumedChunks': len(completed)}
    def checkpoint():
        progress['uploadedChunks'] = [completed[i] for i in sorted(completed)]
        progress['updatedUnix'] = time.time()
        save(progress_path, progress)
    checkpoint()
    transport = runpy.run_path(str(STATE / 'entry.py'), run_name='chunks_transport')
    credentials_path = STATE / 'credentials.json'
    cs = credentials_path.stat()
    if credentials_path.is_symlink() or cs.st_uid != 0 or cs.st_mode & 0o077 or cs.st_size > 8192:
        raise RuntimeError('Unexpected existing credential owner/type/permissions')
    credentials = json.loads(credentials_path.read_text())
    client = transport['API'].GitHub(credentials['resultToken'])
    client.private_repo(REPO, REPO_ID)
    repo = '/repos/' + REPO
    def api(method, path, value=None, allowed=(200, 201)):
        for retry in range(3):  # first attempt plus at most two network retries
            try:
                code, result, _ = client.request(method, repo + path, value)
            except Exception as exc:
                if retry < 2 and (getattr(exc, 'status', None) == 0 or type(exc).__name__ == 'Network'):
                    time.sleep(retry + 1);continue
                raise
            if code in allowed:
                return code, result
            if retry < 2 and code in (0, 429, 500, 502, 503, 504):
                time.sleep(retry + 1);continue
            raise RuntimeError(method + ' ' + path + ' HTTP ' + str(code))
        raise RuntimeError('Unreachable retry state')
    try:
        for chunk in chunks:
            index = chunk['index']
            if index in completed:
                continue
            data = raw[index * CHUNK:index * CHUNK + chunk['bytes']]
            _, blob = api('POST', '/git/blobs', {'encoding': 'base64',
                                              'content': base64.b64encode(data).decode()})
            if blob.get('sha') != chunk['blobSha']:
                raise RuntimeError('ChunkGitSHA1 differs at index ' + str(index))
            completed[index] = chunk
            checkpoint()
        progress['state'] = 'all_blobs_uploaded';checkpoint()
        committed = None
        for _ in range(3):
            _, ref = api('GET', '/git/ref/heads/main')
            head = ref['object']['sha']
            _, parent = api('GET', '/git/commits/' + head)
            _, tree = api('POST', '/git/trees', {'base_tree': parent['tree']['sha'], 'tree': [
                {'path': row['path'], 'mode': '100644', 'type': 'blob', 'sha': row['blobSha']}
                for row in chunks]})
            _, commit = api('POST', '/git/commits', {'message': 'Y only: original evidence64KiB chunks',
                                                  'tree': tree['sha'], 'parents': [head]})
            _, current = api('GET', '/git/ref/heads/main')
            if current['object']['sha'] != head:
                continue
            code, _ = api('PATCH', '/git/refs/heads/main', {'sha': commit['sha'], 'force': False},
                          allowed=(200, 409, 422))
            if code == 200:
                committed = commit['sha'];break
        if committed is None:
            raise RuntimeError('Result ref changed concurrently3times; no force push')
        result = {'success': True, 'archiveSha256': archive_sha, 'archiveBytes': len(raw),
                  'chunkSize': CHUNK, 'chunks': chunks, 'commit': committed,
                  'pathPrefix': prefix, 'resumedChunks': progress['resumedChunks'],
                  'sourceArchive': str(archive), 'readOnlySource': True}
        progress.update(state='committed', commit=committed);checkpoint()
        print(json.dumps(result, separators=(',', ':')), flush=True)
    except BaseException as exc:
        progress.update(state='failed_preserved_for_resume', errorType=type(exc).__name__)
        checkpoint()
        raise


if __name__ == '__main__':
    main()
