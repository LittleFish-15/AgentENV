"""Read independent Host/PSI/cgroup components; missing is never zero."""
import os
from pathlib import Path, PurePosixPath
import re


def memory_fields(text):
    wanted=('MemAvailable','MemFree','Cached','Buffers','Dirty','Writeback','SwapFree','SReclaimable','Shmem')
    raw=dict(line.split(':',1) for line in text.splitlines() if ':' in line)
    result={}
    for key in wanted:
        item=raw.get(key,'').split()
        result[key]=int(item[0])*1024 if len(item)==2 and item[0].isdigit() and item[1]=='kB' else None
    return result


def host_observation(proc=Path('/proc')):
    result={'memoryBytes':{},'pressure':{},'errors':{},'wholeHostIdleEstablished':False}
    try:result['memoryBytes']=memory_fields((proc/'meminfo').read_text())
    except (OSError,ValueError) as error:result['errors']['meminfo']=type(error).__name__
    try:result['loadAverage']=(proc/'loadavg').read_text().strip()
    except OSError as error:result['errors']['loadavg']=type(error).__name__
    for name in ('cpu','memory','io'):
        try:result['pressure'][name]={'available':True,'text':(proc/'pressure'/name).read_text()}
        except OSError as error:
            result['pressure'][name]={'available':False,'errorType':type(error).__name__}
            result['errors']['pressure/'+name]=type(error).__name__
    result['available']=any(v is not None for v in result['memoryBytes'].values())
    result['partial']=bool(result['errors']) or any(v is None for v in result['memoryBytes'].values())
    return result


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
