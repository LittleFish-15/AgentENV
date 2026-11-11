"""One-time transport-only entry upgrade. No application or credential edits."""
import fcntl,hashlib,os,pathlib,stat
OLD='769f854fb46c0a514a01e27ce7b383090b2bd1d6f90307d04d9d2605bd515234'
NEW='a60349eb2679f241e4f5fb46a6b88c8b6f51a6c48f80660d1848988718a9619d'
BEFORE=b"        else:\n            cache=STATE/'source-cache.git'\n"
AFTER=b"        elif 'sourceInlineBase64' in job:\n            encoded=job['sourceInlineBase64']\n            need(isinstance(encoded,str) and 0<len(encoded)<=349528,'Inline task source exceeds bound')\n            raw=base64.b64decode(encoded,validate=True);code=200\n            print('ROOT_TASK_SOURCE_RECEIVED=inline_control_document',flush=True)\n        else:\n            cache=STATE/'source-cache.git'\n"

def transform(raw):
    current=hashlib.sha256(raw).hexdigest()
    if current==NEW:return raw
    assert current==OLD and raw.count(BEFORE)==1,'Entry differs; preserve and inspect'
    updated=raw.replace(BEFORE,AFTER,1)
    assert hashlib.sha256(updated).hexdigest()==NEW
    compile(updated,'entry.py','exec')
    return updated

def main():
    assert os.getuid()==os.geteuid()==0,'Run as root'
    assert pathlib.Path('/etc/machine-id').read_text().strip()=='9c4987ac1e5849409b53b20724f12d34','Wrong machine'
    assert pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()=='f05c9a4f-bf8b-49f2-a3ea-4cdd0b5fc581','Boot changed; preserve and reconcile'
    os.umask(0o077)
    root=pathlib.Path('/home/jwk/y-aenv-control');folder=root/'relay-debian-clean-20261111';entry=folder/'entry.py'
    for path in (root,folder,entry):
        assert path.resolve()==path and path.stat().st_uid==0 and not path.stat().st_mode&0o022,'Unsafe entry path'
    fd=os.open(folder/'operation.lock',os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        assert stat.S_ISREG(os.fstat(fd).st_mode) and os.fstat(fd).st_uid==0
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        raw=entry.read_bytes();updated=transform(raw)
        if raw!=updated:
            backup=folder/'entry.before-inline007.py'
            if backup.exists():assert backup.resolve()==backup and backup.stat().st_uid==0 and backup.read_bytes()==raw
            else:
                with backup.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
            temporary=folder/'entry.inline007.next'
            if temporary.exists():assert temporary.resolve()==temporary and temporary.stat().st_uid==0 and temporary.read_bytes()==updated
            else:
                with temporary.open('xb') as f:f.write(updated);f.flush();os.fsync(f.fileno())
            assert entry.read_bytes()==raw,'Entry changed during upgrade'
            os.replace(temporary,entry)
            directory=os.open(folder,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(directory)
            finally:os.close(directory)
        print('Y_ENTRY_INLINE_TRANSPORT_READY='+NEW,flush=True)
    finally:os.close(fd)
    os.execv('/bin/bash',['bash',str(root/'root-start.sh')])
if __name__=='__main__':main()
