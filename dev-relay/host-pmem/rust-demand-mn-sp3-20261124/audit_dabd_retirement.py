"""Read-only inventory of the old dabd generation's remaining ownership evidence."""
import argparse
import hashlib
import json
import os
import re
import stat
import uuid
from pathlib import Path

RUN = 'dabd65d32a1c5c3e91a994bbcbbb9e6f'
POOL = '01a21fe4-7e16-7442-b4e7-592d12958c40'
OBJECT = 'aenv_01a21fe47e167442b4e7592d12958c40'
VOLUMES = {'agent1': '01a21fe3-9305-7e31-ac60-cb28b9532df5',
           'agent2': '01a21fe1-048a-7740-94a6-62f9e6927ecd'}
LAYOUT = __import__('struct').Struct('<II16sIIII7Q')

def read_json(path):
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(value, dict):
            return {'status': 'invalid-json-object'}
        keep = {k: value[k] for k in ('run', 'node', 'phase', 'volume', 'pools', 'closed',
                'faulted', 'released', 'finalizeAcknowledged', 'initializeAcknowledged') if k in value}
        return {'status': 'present', 'facts': keep}
    except FileNotFoundError:
        return {'status': 'absent'}
    except (OSError, ValueError) as e:
        return {'status': 'unreadable', 'error': type(e).__name__}

def shmdevs():
    matches, unreadable = [], 0
    for path in sorted(Path('/sys/devices/obmm').glob('obmm_shmdev*'))[:256]:
        try:
            size = int((path/'priv_len').read_text().strip())
            raw = (path/'priv').read_bytes()[:512]
            if 204 <= size <= len(raw) and raw[152:204].partition(b'\0')[0] == OBJECT.encode():
                matches.append({'name': path.name, 'type': (path/'type').read_text().strip()[:64]})
        except (OSError, ValueError):
            unreadable += 1
    return {'matches': matches, 'unreadable': unreadable}

def exact_volume(name):
    import fcntl, errno, struct
    dev = Path('/dev/obmm_pmem')
    if not dev.exists(): return {'status':'device-absent'}
    wire = bytearray(LAYOUT.size)
    struct.pack_into('<II16s', wire, 0, 1, 0, uuid.UUID(name).bytes)
    fd = os.open(str(dev), os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
    try:
        try: fcntl.ioctl(fd, 0xc060b801, wire, True)
        except OSError as e:
            if e.errno == errno.ENOENT: return {'status':'absent'}
            return {'status':'query-error','errno':e.errno}
    finally: os.close(fd)
    row = LAYOUT.unpack(wire)
    return {'status':'present','uuid':name,'id':row[3],'state':row[4],'bytes':row[7],
            'openers':row[8],'activeIo':row[9],'blockReads':row[10],
            'blockBytes':row[11],'daxAccesses':row[12],'daxSpanBytes':row[13]}

def main():
    p=argparse.ArgumentParser(); p.add_argument('--node',choices=('agent1','agent2'),required=True)
    p.add_argument('--boot-id',required=True); p.add_argument('--machine-id',required=True); a=p.parse_args()
    assert os.geteuid()==0 and os.uname().nodename.split('.')[0]==a.node
    assert Path('/proc/sys/kernel/random/boot_id').read_text().strip()==a.boot_id
    assert Path('/etc/machine-id').read_text().strip()==a.machine_id
    root=Path('/etc/aenv/ub'); sdk=Path('/var/lib/aenv-ub-sdk'); run=RUN
    paths={'rootRun':root/('relay-'+run)/'device-state/root.json',
           'sdkRun':sdk/('relay-'+run)/'state/sdk.json',
           'sdkDirectory':sdk/('relay-'+run)/('directory-'+run+'.json'),
           'legacyRootRun':root/('run-'+run)/'device-state/root.json',
           'legacySdkRun':sdk/('run-'+run)/'state/sdk.json',
           'legacyDirectory':sdk/('directory-'+run+'.json')}
    facts={k:{'path':str(v),'journal':read_json(v)} for k,v in paths.items()}
    adapter=Path('/opt/aenv/libaenv-ub.so')
    try:
        st=adapter.lstat(); adapter_f={'present':stat.S_ISREG(st.st_mode),'uid':st.st_uid,
            'mode':oct(stat.S_IMODE(st.st_mode)),'sha256':hashlib.sha256(adapter.read_bytes()).hexdigest()}
    except FileNotFoundError: adapter_f={'present':False}
    print(json.dumps({'status':'DABD_RETIREMENT_READONLY_AUDIT','node':a.node,'run':RUN,
        'volume':exact_volume(VOLUMES[a.node]),'journals':facts,'poolObject':OBJECT,
        'shmdevs':shmdevs(),'adapter':adapter_f},sort_keys=True))
if __name__=='__main__': main()
