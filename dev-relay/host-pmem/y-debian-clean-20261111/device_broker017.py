"""Grant only newly created ublk device inodes proven to belong to this unit."""
import ctypes,hashlib,json,os,pathlib,re,select,stat,struct,subprocess,time
ROOT=pathlib.Path('/run/jwk-aenv-y-clean-20261111')
CONFIG=json.loads((ROOT/'broker-config017.json').read_text())
UID=CONFIG['uid'];CGROUP='/system.slice/'+CONFIG['unit'];DAEMON_SHA=CONFIG['daemon_sha256']
VERIFIED={}
def signature(st):return (st.st_dev,st.st_ino,st.st_rdev)
def process(pid):
    path=pathlib.Path('/proc',str(pid));status={a:b.strip() for line in (path/'status').read_text().splitlines() if ':' in line for a,b in [line.split(':',1)]}
    assert [int(v) for v in status['Uid'].split()]==[UID]*4
    groups=[x.split(':',2)[2] for x in (path/'cgroup').read_text().splitlines()]
    assert any(x==CGROUP or x.startswith(CGROUP+'/') for x in groups)
    start=(path/'stat').read_text().rsplit(')',1)[1].split()[19]
    executable=path/'exe';st=executable.stat();key=(pid,start,st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns)
    if key not in VERIFIED:
        with executable.open('rb') as f:assert hashlib.file_digest(f,'sha256').hexdigest()==DAEMON_SHA
        VERIFIED[key]=True
    return start
def prestart_daemon():
    candidates=[]
    for path in pathlib.Path('/proc').iterdir():
        if not path.name.isdigit():continue
        try:
            if path.stat().st_uid!=UID:continue
            if (path/'comm').read_text().strip()!='uvm-ublk-daemon':continue
            candidates.append(int(path.name))
        except OSError:continue
    assert len(candidates)==1,'Ambiguous or absent jwk ublk daemon'
    pid=candidates[0];return pid,process(pid)
def grant(path,excluded):
    match=re.fullmatch(r'ublk([cb])(\d+)',path.name)
    if not match:return False
    before=path.lstat()
    if signature(before) in excluded or before.st_uid==UID:return False
    assert (stat.S_ISCHR(before.st_mode) if match[1]=='c' else stat.S_ISBLK(before.st_mode))
    fd=os.open(path,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        held=os.fstat(fd);assert signature(held)==signature(before)
        query=subprocess.run([CONFIG['query'],match[2]],env={'PATH':'/usr/bin:/bin'},capture_output=True,text=True,timeout=3)
        if query.returncode:raise RuntimeError('Read-only kernel owner query failed: '+query.stderr[-1500:])
        info=json.loads(query.stdout);pid=int(info['pid']);assert info['id']==int(match[2])
        assert info['ownerUid']==UID and info['ownerGid']==CONFIG['gid'],'Kernel owner differs'
        if 0<pid<2147483647:start=process(pid);phase='started'
        else:pid,start=prestart_daemon();phase='prestart-owner-verified'
        assert signature(path.lstat())==signature(held)
        assert process(pid)==start
        # Hold the verified inode, so device ID reuse cannot redirect chown.
        libc=ctypes.CDLL(None,use_errno=True)
        result=libc.fchownat(fd,b'',ctypes.c_uint(UID),ctypes.c_uint(0xffffffff),0x1000)
        assert result==0,ctypes.get_errno()
        print(json.dumps({'granted':path.name,'uid':UID,'daemonPid':pid,'phase':phase,'kernelOwnerUid':info['ownerUid']}),flush=True)
        return True
    finally:os.close(fd)
def main():
    assert os.getuid()==os.geteuid()==0
    excluded=set(tuple(row) for row in CONFIG['excluded'])
    libc=ctypes.CDLL(None,use_errno=True)
    fd=libc.inotify_init1(os.O_NONBLOCK|os.O_CLOEXEC);assert fd>=0
    assert libc.inotify_add_watch(fd,b'/dev',0x100|0x80|0x4|0x200)>=0
    (ROOT/'broker-ready017.json').write_text(json.dumps({'pid':os.getpid(),'uid':0})+'\n')
    pending={p.name:(time.monotonic(),time.monotonic()+3) for p in pathlib.Path('/dev').glob('ublk[cb]*') if re.fullmatch(r'ublk[cb]\d+',p.name)}
    reported=set()
    while True:
        if select.select([fd],[],[],.02)[0]:
            data=os.read(fd,65536);offset=0
            while offset+16<=len(data):
                _,mask,_,size=struct.unpack_from('iIII',data,offset)
                name=data[offset+16:offset+16+size].split(b'\0',1)[0].decode(errors='replace');offset+=16+size
                if re.fullmatch(r'ublk[cb]\d+',name):
                    if mask&0x200:pending.pop(name,None)
                    else:pending[name]=(time.monotonic(),time.monotonic()+3)
        for name,(next_time,deadline) in list(pending.items()):
            if time.monotonic()<next_time:continue
            if time.monotonic()>deadline:pending.pop(name,None);continue
            try:
                path=pathlib.Path('/dev')/name
                st=path.lstat();key=signature(st)
                if key in excluded or st.st_uid==UID or grant(path,excluded):pending.pop(name,None);continue
            except (AssertionError,OSError,ValueError,RuntimeError,subprocess.TimeoutExpired) as error:
                detail=(name,type(error).__name__,str(error)[-1500:])
                if detail not in reported:
                    print(json.dumps({'pendingDevice':name,'errorType':detail[1],'detail':detail[2]}),flush=True);reported.add(detail)
            pending[name]=(time.monotonic()+.02,deadline)
if __name__=='__main__':main()
