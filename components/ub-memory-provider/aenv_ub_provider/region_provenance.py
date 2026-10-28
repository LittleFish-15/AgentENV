"""Derived OBMM origin evidence under the pinned UBSE metadata schema.

No raw physical addresses, user metadata or authentication values are returned.
Unknown schemas fail closed instead of equating object hashes with sharing.
"""
import hashlib
import os
from pathlib import Path
import re
import stat
import struct

from .host_dax_demand import require

PREFIX=struct.Struct('<BBIII52s16sQQQ16s16sQI52s')
ENGINE_SHA='22ce7d2f4309765d18e4df41a8a2941aacd023cac46d8f135aee0cd4a2e19d45'


def text(data):
    value=data.split(b'\0',1)[0].decode('ascii')
    require(bool(value),'Empty origin identity')
    return value


def collect(pid,ticks,segments,object_name):
    def identity():return (Path('/proc')/str(pid)/'stat').read_text().rsplit(')',1)[1].split()[19]
    require(identity()==ticks,'Root helper PID changed')
    expected={row['rdev'] for row in segments};rows={}
    for fd in (Path('/proc')/str(pid)/'fd').iterdir():
        try:
            target=os.readlink(fd);match=re.fullmatch('/dev/obmm_shmdev([0-9]+)',target)
            if not match:continue
            info=fd.stat()
            if info.st_rdev not in expected:continue
            require(stat.S_ISCHR(info.st_mode),'OBMM region FD is not character device')
            number=int(match[1]);root=Path('/sys/devices/obmm')/('obmm_shmdev'+str(number))
            kind=(root/'type').read_text().strip();size=int((root/'size').read_text().strip(),0)
            count=int((root/'priv_len').read_text().strip())
            require(2+PREFIX.size<=count<=512,'Unsupported private origin prefix size')
            data=(root/'priv').read_bytes();require(len(data)==count,'Truncated origin metadata')
            fields=PREFIX.unpack_from(data,2)
            require(fields[0]==1 and fields[1]==2 and kind in ('export','import'),'Unsupported origin schema/type')
            require(text(fields[14])==object_name,'Region is not the signed SDK object')
            origin={'exportNodeId':text(fields[10]),'exportMemId':number if kind=='export' else fields[12]}
            rows[info.st_rdev]={'localRegion':number,'kind':kind,'bytes':size,'origin':origin,
                              'ranges':[r for r in segments if r['rdev']==info.st_rdev]}
        except FileNotFoundError:continue
    require(set(rows)==expected and identity()==ticks,'Incomplete or unstable OBMM mapping evidence')
    return list(rows.values())


def attest_engine(pid):
    path=Path(os.readlink(Path('/proc')/str(pid)/'exe')).resolve(strict=True)
    info=path.stat();require(info.st_uid==0 and not info.st_mode&0o022 and info.st_size==9704056,'Unexpected engine executable')
    digest=hashlib.sha256()
    with path.open('rb') as f:
        for data in iter(lambda:f.read(1024**2),b''):digest.update(data)
    require(digest.hexdigest()==ENGINE_SHA,'Runtime engine differs from the reviewed origin schema')
    return {'engineSha256':ENGINE_SHA,'schema':'ubs-engine-1.0.1-custom-v1-prefix'}
