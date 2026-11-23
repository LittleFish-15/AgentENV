"""Return saved upload checkpoints and compact results only; no new uploads."""
from pathlib import Path
import csv
import hashlib
import json
import os
import re
import statistics

assert os.geteuid() == 0
state = Path('/home/jwk/y-aenv-control/relay-debian-clean-20261111')
job = state / 'jobs/y-aenv-stop-cause-20261123-recovery8-node-y'
source = Path('/home/jwk/aenv-stop-cause-20261123-Y-run8')
assert source.resolve() == source and job.resolve() == job
paths = list(job.glob('upload-chunks-*.json'))
assert len(paths) == 1, 'Expected one preserved upload checkpoint'
path = paths[0]
assert path.stat().st_size < 1024**2 and not path.is_symlink()
checkpoint = json.loads(path.read_text())
chunks = checkpoint['uploadedChunks']
size, step = checkpoint['archiveBytes'], checkpoint['chunkSize']
assert step == 65536 and len(chunks) == (size + step - 1) // step
assert sum(c['bytes'] for c in chunks) == size
for i, chunk in enumerate(chunks):
    assert chunk['index'] == i and re.fullmatch('[0-9a-f]{40}', chunk['blobSha'])
    assert re.fullmatch('[0-9a-f]{64}', chunk['sha256'])
    assert chunk['bytes'] == min(step, size - i * step)
archive = Path(checkpoint['sourceArchive'])
assert archive.parent == job / 'run8-export' and archive.is_file() and not archive.is_symlink()
assert archive.stat().st_size == size
with archive.open('rb') as stream:
    assert hashlib.file_digest(stream, 'sha256').hexdigest() == checkpoint['archiveSha256']
result = json.loads((source / 'result.json').read_text())
groups = {}
for name in ('baseline-c1', 'baseline-c100', 'traced-c1', 'traced-c100'):
    folder = source / 'lifecycle' / name
    summary = json.loads((folder / 'summary.json').read_text())
    groups[name] = {'valid': summary['valid'], 'rounds': summary['rounds_succeeded'],
                    'phases': {phase: {k: summary[phase].get(k) for k in ('succeeded', 'failed', 'mean_sec', 'p95_sec', 'wall_mean_per_round_sec')}
                               for phase in ('create', 'pause', 'resume', 'delete')}}
print('SAVED_RESULTS=' + json.dumps({'result': result, 'groups': groups}, separators=(',', ':')), flush=True)
print('UPLOAD_INDEX=' + json.dumps({k: checkpoint[k] for k in ('archiveSha256', 'archiveBytes', 'chunkSize', 'sourceArchive', 'state', 'uploadedChunks')}, separators=(',', ':')), flush=True)
