"""Finite file replacement with explicit rollback, for an already stopped Runtime.

Caller must hold the cohort lock and verify service/process retirement. This
module never stops or starts services. It preserves immutable before/after copies
and refuses to overwrite any third, unknown file value during rollback.
"""
import hashlib,json,os,stat,uuid
from pathlib import Path,PurePosixPath
ALLOWED={'bin/server','libexec/native_prepare.py','libexec/native_service.py',
 'definition-native.json','installation.json','input-manifest.json','definition.json','prepare.json'}

def require(ok,reason):
    if not ok:raise RuntimeError(reason)

def sync_parent(path):
    if os.name!='posix':return
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)

def stable(path,limit=128*1024**2):
    require(path.resolve(strict=True)==path,'Redirected transaction file')
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0))
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and 0<before.st_size<=limit,'Unexpected transaction file')
        data=stream.read(limit+1);after=os.fstat(stream.fileno())
    stamp=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    require(stamp(before)==stamp(after) and len(data)==before.st_size,'Transaction input changed')
    current=path.stat()
    if os.name=='posix':
        require(stamp(after)==stamp(current),'Transaction path identity changed')
    else:
        # The Windows local test host reports different inode/device values for
        # fstat and path stat. Target activation requires Linux and uses the
        # complete identity check above, including inode and device.
        require((after.st_size,after.st_mtime_ns)==(current.st_size,current.st_mtime_ns),
            'Local transaction fixture changed')
    return data,{'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),
        'uid':before.st_uid,'gid':before.st_gid,'mode':stat.S_IMODE(before.st_mode)}

class Transaction:
    def __init__(self,root,stage,manifest):
        self.root=Path(root);self.stage=Path(stage);self.manifest=manifest
        require(self.root.resolve(strict=True)==self.root and self.stage.resolve(strict=True)==self.stage
            and self.stage.is_relative_to(self.root/'updates'),'Transaction is outside its owned update directory')
        require(set(manifest)==ALLOWED,'Unexpected file replacement scope')
        for relative,row in manifest.items():
            p=PurePosixPath(relative)
            require(not p.is_absolute() and '..' not in p.parts and set(row)=={'before','after'},'Malformed transaction manifest')
            for pin in row.values():
                require(set(pin)=={'sha256','bytes','uid','gid','mode'} and
                    type(pin['bytes']) is int and 0<pin['bytes']<=128*1024**2 and
                    len(pin['sha256'])==64 and all(c in '0123456789abcdef' for c in pin['sha256']),
                    'Malformed file pin')
            require(all(row['before'][key]==row['after'][key] for key in ('uid','gid','mode')),
                'Update must preserve file ownership and mode')
        self.identity=hashlib.sha256(json.dumps(manifest,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        self.journal=self.stage/'swap-state.json'

    def pin(self,path,expected):
        data,found=stable(path)
        require(found==expected,'Unknown or changed file: '+str(path))
        return data

    def write_journal(self,value):
        value={**value,'manifestSha256':self.identity}
        if self.journal.exists():
            old,_=stable(self.journal,65536)
            require(json.loads(old).get('manifestSha256')==self.identity,'Different transaction journal preserved')
        target=self.stage/('swap-state.'+uuid.uuid4().hex+'.tmp')
        with target.open('xb') as out:
            out.write((json.dumps(value,indent=2)+'\n').encode());out.flush();os.fsync(out.fileno())
        owner=next(iter(self.manifest.values()))['before']
        if os.name=='posix':os.chown(target,owner['uid'],owner['gid']);os.chmod(target,0o600)
        os.replace(target,self.journal);sync_parent(self.stage)

    def install(self,relative,which,expected_current):
        destination=self.root/relative
        self.pin(destination,expected_current)
        pin=self.manifest[relative][which]
        data=self.pin(self.stage/which/relative,pin)
        require(destination.parent.resolve(strict=True)==destination.parent,'Redirected destination parent')
        temporary=destination.with_name('.aenv-update-'+uuid.uuid4().hex)
        with temporary.open('xb') as out:
            out.write(data);out.flush();os.fsync(out.fileno())
        if os.name=='posix':os.chown(temporary,pin['uid'],pin['gid'])
        os.chmod(temporary,pin['mode'])
        self.pin(temporary,pin);self.pin(destination,expected_current)
        os.replace(temporary,destination);sync_parent(destination.parent)
        self.pin(destination,pin)

    def validate(self,allow_after=False):
        for relative,row in self.manifest.items():
            self.pin(self.stage/'before'/relative,row['before'])
            self.pin(self.stage/'after'/relative,row['after'])
            _,actual=stable(self.root/relative)
            require(actual==row['before'] or allow_after and actual==row['after'],
                'Unknown live file; no overwrite: '+relative)

    def apply(self):
        require(not self.journal.exists() and not self.journal.is_symlink(),'Existing transaction requires explicit rollback/reconciliation')
        self.validate()
        state={'phase':'applying','applied':[],'pending':None}
        self.write_journal(state)
        try:
            for relative in sorted(self.manifest):
                state['pending']=relative;self.write_journal(state)
                self.install(relative,'after',self.manifest[relative]['before'])
                state['applied'].append(relative);state['pending']=None;self.write_journal(state)
            state['phase']='applied';self.write_journal(state)
        except BaseException:
            state['phase']='interrupted';self.write_journal(state);raise
        return state

    def rollback(self):
        raw,_=stable(self.journal,65536);state=json.loads(raw)
        require(state.get('manifestSha256')==self.identity and state.get('phase') in
            ('applying','interrupted','applied','rolling_back','rolled_back'),'No recognized transaction to roll back')
        self.validate(allow_after=True)  # Check every target before changing any.
        state['phase']='rolling_back';self.write_journal(state)
        for relative in sorted(self.manifest,reverse=True):
            _,actual=stable(self.root/relative)
            if actual==self.manifest[relative]['after']:
                self.install(relative,'before',actual)
        state.update(phase='rolled_back',pending=None);self.write_journal(state)
        self.validate();return state
