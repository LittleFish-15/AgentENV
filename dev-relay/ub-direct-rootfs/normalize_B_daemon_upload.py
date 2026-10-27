"""Normalize only the checksum-pinned uploaded daemon, without editing its inode."""
import hashlib,json,os,stat,uuid
from pathlib import Path
ROOT=Path('/home/jwk/agent')
PATH=ROOT/'uvm-ublk-daemon-private-delete-v1'
SIZE=24758576
SHA='5291c267777cd91c4b853c6d40720e8d87200b2a0162024782534c4126cba726'

def need(ok,why):
    if not ok:raise RuntimeError(why)

def identity(meta):
    return tuple(getattr(meta,k) for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns'))

def allowed(meta):
    return stat.S_ISREG(meta.st_mode) and meta.st_uid in (0,1204) and meta.st_size==SIZE

def main():
    need(os.getuid()==os.geteuid()==0 and os.uname().nodename=='agent1','B/agent1 root only')
    need(ROOT.resolve(strict=True)==ROOT and PATH.parent==ROOT,'Upload directory redirected')
    named=PATH.lstat()
    before={'uid':named.st_uid,'gid':named.st_gid,'links':named.st_nlink,'mode':oct(stat.S_IMODE(named.st_mode)),
            'regularFile':stat.S_ISREG(named.st_mode),'symlink':stat.S_ISLNK(named.st_mode),'bytes':named.st_size}
    print('UPLOADED_DAEMON_METADATA '+json.dumps(before),flush=True)
    source=PATH.resolve(strict=True) if stat.S_ISLNK(named.st_mode) else PATH
    need(named.st_uid in (0,1204) and source.is_relative_to(ROOT) and source.resolve(strict=True)==source,
         'Upload link/owner is outside the authorized artifact directory; no changes made')
    source_meta=source.lstat()
    need(allowed(source_meta),'Upload content must be a regular root/jwk-owned file of the exact expected length; no changes made')
    fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as stream:
        opened=os.fstat(stream.fileno());need(identity(opened)==identity(source_meta),'Upload replaced before read')
        raw=stream.read(SIZE+1);after=os.fstat(stream.fileno())
        need(identity(opened)==identity(after),'Upload changed during read')
    need(len(raw)==SIZE and hashlib.sha256(raw).hexdigest()==SHA,'Uploaded daemon SHA256 differs; no changes made')
    temp=ROOT/('.ub-daemon-upload-normalized-'+uuid.uuid4().hex)
    created=False
    try:
        fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);created=True
        with os.fdopen(fd,'wb') as stream:
            need(stream.write(raw)==len(raw),'Incomplete artifact copy')
            stream.flush();os.fchown(stream.fileno(),1204,1205);os.fchmod(stream.fileno(),0o600);os.fsync(stream.fileno())
        need(identity(PATH.lstat())==identity(named) and identity(source.lstat())==identity(source_meta),
             'Upload changed before replacement; preserve it')
        # Replace only the uploaded pathname with identical verified bytes.
        # Do not chmod a hard-linked inode used by another pathname/service.
        os.replace(temp,PATH);created=False
        directory=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:
        if created:temp.unlink()
    result=PATH.lstat()
    need(stat.S_ISREG(result.st_mode) and result.st_uid==1204 and result.st_gid==1205
         and result.st_nlink==1 and stat.S_IMODE(result.st_mode)==0o600,'Normalized artifact metadata differs')
    need(hashlib.sha256(PATH.read_bytes()).hexdigest()==SHA,'Normalized artifact content differs')
    print(json.dumps({'status':'B_UPLOADED_DAEMON_NORMALIZED_VERIFIED','path':str(PATH),'sha256':SHA,
        'bytes':SIZE,'ownerUID':1204,'ownerGID':1205,'mode':'0600','links':1,
        'oldMetadata':before,'servicesChanged':False,'binaryRebuilt':False}),flush=True)

if __name__=='__main__':main()
