import fcntl,hashlib,json,os,platform,types,uuid
from pathlib import Path
assert os.getuid()==os.geteuid()==0
b=Path('/var/lib/agentenv-hpab-services-v1');p=b/'entry.py';raw=p.read_bytes()
assert p.resolve()==p and p.stat().st_uid==0
assert hashlib.sha256(raw).hexdigest()=='b072e78f6cd206537a1b06dd1b4efbfaa98fbe38213a3cc944e900764abae927'
m=types.ModuleType('approved');m.__file__=str(p);exec(compile(raw,str(p),'exec'),m.__dict__)
api=m.module('api');a=json.loads(m.read(b/'private/approval.json'))
n={'server1':'node-a','agent1':'node-b'}[platform.node()]
assert a['nodes'][n]['identity']==m.identity()
os.umask(0o077)
fd=os.open(b/'private/operation.lock',os.O_RDWR|os.O_NOFOLLOW)
with os.fdopen(fd,'a') as lock:
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    jp=b/'private/journal.json';j=json.loads(m.read(jp))
    assert set(j['steps'])=={'export_code','compile_helpers'}
    assert j['steps']['export_code']['state']=='done' and j['steps']['compile_helpers']['state']=='intent'
    assert not j['units'] and j['SDK_called'] is False
    d=b/'private'/('helper-fix-'+uuid.uuid4().hex);d.mkdir(mode=0o700)
    m.put(d/'journal-before.json',m.read(jp),mode=0o600)
    hashes={};logs=[]
    for name in ('sdk_lookup','ublk_owner'):
        src=d/(name+'.c');m.put(src,m.source(name),mode=0o600)
        argv=[m.tool('gcc'),'-std=c11','-O2','-Wall','-Wextra','-Werror','-include','sys/types.h',str(src),'-o',str(d/name)]
        if name=='sdk_lookup':argv+=['-lubsm_sdk','-Wl,-rpath,/usr/lib64']
        r=m.cmd(argv,120,check=False)
        logs.append({'name':name,'exitCode':r.returncode,'stderr':r.stderr[:32768].decode(errors='replace')})
        api.atomic(d/'compile.json',logs)
        assert r.returncode==0, 'Compile failed; exact diagnostics preserved in '+str(d)
        hashes[name]=m.digest(d/name)
    for name in hashes:
        dest=b/'public'/name
        assert not dest.is_symlink() and (not dest.exists() or dest.stat().st_uid==0)
        os.chmod(d/name,0o755);os.replace(d/name,dest)
    j['compileRepair']={'directory':str(d),'change':'compiler preinclude sys/types.h; original embedded sources unchanged','originalFailure':j.get('failure'),'helperSha256':hashes}
    j['steps']['compile_helpers']={'state':'done','result':hashes};j['phase']='compile_helpers_repaired_confirmed'
    t=d/'journal-after.json';m.put(t,m.wire(j)+b'\n',mode=0o600);os.replace(t,jp)
    sync=os.open(jp.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(sync);os.close(sync)
print('HELPER_TYPES_FIXED_CONTINUING_SAME_TRANSACTION',flush=True)
os.execv('/usr/bin/python3',['/usr/bin/python3','-I','-B',str(p),'start'])