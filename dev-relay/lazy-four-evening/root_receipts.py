"""Root-owned replies outside user-owned deployment trees; requests stay separate."""
import json
import os
from pathlib import Path
import re
import stat

RECEIPT_BASE = Path('/run/agentenv-lazy-four')


def receipt_directory(nonce):
    if not isinstance(nonce,str) or not re.fullmatch('[0-9a-f]{32}',nonce):
        raise RuntimeError('Invalid root receipt generation')
    return RECEIPT_BASE/nonce


def trusted_receipt_directory(directory):
    if directory.parent!=RECEIPT_BASE or receipt_directory(directory.name)!=directory:
        raise RuntimeError('Receipt outside exact generation')
    for path in (RECEIPT_BASE.parent,RECEIPT_BASE,directory):
        meta=path.lstat()
        if (path.resolve(strict=True)!=path or not stat.S_ISDIR(meta.st_mode)
                or meta.st_uid!=0 or stat.S_IMODE(meta.st_mode)&0o022
                or not stat.S_IMODE(meta.st_mode)&0o001):
            raise RuntimeError('Root receipt hierarchy is not root-owned and protected')


def create_receipt_directory(nonce):
    if os.geteuid()!=0:raise RuntimeError('Only root creates receipt generations')
    parent=RECEIPT_BASE.parent
    meta=parent.lstat()
    if parent.resolve(strict=True)!=parent or meta.st_uid!=0 or not stat.S_ISDIR(meta.st_mode) or stat.S_IMODE(meta.st_mode)&0o022:
        raise RuntimeError('Unexpected root receipt parent')
    try:
        RECEIPT_BASE.mkdir(mode=0o755)
        os.chmod(RECEIPT_BASE,0o755)  # Root's restrictive umask must not block the reader.
    except FileExistsError:pass
    base=RECEIPT_BASE.lstat()
    if RECEIPT_BASE.resolve(strict=True)!=RECEIPT_BASE or base.st_uid!=0 or not stat.S_ISDIR(base.st_mode) or stat.S_IMODE(base.st_mode)&0o022 or not stat.S_IMODE(base.st_mode)&0o001:
        raise RuntimeError('Unexpected root receipt base')
    directory=receipt_directory(nonce)
    directory.mkdir(mode=0o755)  # Never reuse an existing root session, even empty.
    os.chmod(directory,0o755)
    trusted_receipt_directory(directory)
    return directory


def read_root_receipt(path,nonce):
    directory=receipt_directory(nonce)
    if path.parent!=directory or not re.fullmatch(r'(ready|[0-9]{4,5}\.reply)\.json',path.name):
        raise RuntimeError('Unexpected root receipt name or generation')
    trusted_receipt_directory(directory)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_uid!=0 or before.st_nlink not in (1,2) or stat.S_IMODE(before.st_mode)&0o022 or before.st_size>1024**2:
            raise RuntimeError('Unexpected root receipt file')
        raw=stream.read(1024**2+1);after=os.fstat(stream.fileno())
    if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) or len(raw)!=before.st_size:
        raise RuntimeError('Root receipt changed while reading')
    value=json.loads(raw)
    if not isinstance(value,dict) or value.get('nonce')!=nonce:raise RuntimeError('Root receipt nonce differs')
    return value


def validate_root_result(value,nonce,sequence,operation):
    if (value.get('nonce')!=nonce or value.get('sequence')!=sequence or value.get('operation')!=operation
            or value.get('status') not in ('ROOT_OPERATION_COMPLETED','ROOT_OPERATION_STOPPED_PRESERVE_STATE')):
        raise RuntimeError('Root operation outcome is unconfirmed; preserve request')
    return value['status']=='ROOT_OPERATION_COMPLETED'
