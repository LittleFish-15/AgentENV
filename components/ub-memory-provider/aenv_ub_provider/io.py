import json
import os
from pathlib import Path
import sys
import uuid

CHUNK = 1024 * 1024

def atomic_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if sys.platform == 'linux':
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()



def read_json(path):
    with Path(path).open('rb') as stream:
        raw = stream.read(CHUNK + 1)
    if len(raw) > CHUNK:
        raise ValueError('JSON input exceeds 1MiB')
    return json.loads(raw)
