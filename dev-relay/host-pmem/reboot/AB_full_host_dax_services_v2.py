"""Approval-bound two-node full Host-DAX service start and explicit recovery.

No Guest is created. No target SSH, force unload, whole-host cache drop, ordinary
lower fallback, or original enrollment modification. Source bytes are pinned;
live target state, SDK ACKs and peer receipts determine actual success.
"""
import argparse
import base64
import ctypes
import fcntl
import grp
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import platform
import pwd
import re
import secrets
import socket
import stat
import subprocess
import sys
import time
import types
import zlib

EMBEDDED={'api': {'sha256': 'b958c459c09db2fe72d508762e8bdab06bd642bfc2f33c6723462ac45353fdcd', 'bytes': 31491, 'z64': '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'}, 'maintenance': {'sha256': 'b05df5d3cd17db1b0d7d51fc7b3f53d5341d256fc74c0788dadc242f89e4360e', 'bytes': 21677, 'z64': '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'}, 'sdk_lookup_python': {'sha256': 'a14ee3c659dc86c2e9b4fcc505edba1d501c9b7b014ce53a3fc1cbe815a51470', 'bytes': 2401, 'z64': 'eNqNVluPmzgUfudXWPMCrAgBQghJysO009WOWnW7bfcpipAxJnELNrJNOtmq/32PgUyYnbZaHgj2uX3nnpubm786Ks+I44YqpI9SdIcj/FJEH5jSjB/Q7cv72QLhEreayvnHuzdbxAUIaHaiiIimZTV8C+5b1rvHe6VlR3QnKWIKlZSIkpY++gR6W8Y5LRHosRVSx4Y2M8YrMUqgI1YoCuLU6hjXSYzu7xRyXoQr9Ia9dLcIo0OHJShDuGYHowh4gIREp9tOo6KrKioRJgCsESXW4BXTvvUnr8+9W6UgXUO5BklJASBHBptB2SkD8W/+hYuvHIiqqzUg1KIF5xumVO/jzc2NxZpWSI2IPrdUeYD4WLPC+6wE94TyJPXUWVmVFA1qsTY0NEq8h6N1e3f7/tPrD/nHP24zexHTMiTLJEmKZRKlhCxWRUxWy2q9xHG8guuAlGG4pkUQVUFZpWRNaLjEy7ggZYUD24JADqrSNEmTgsQ0TdYkieOIFqsyTcMoxVG5oFWZRjFwrBMSp+vVIq5IGhRxso4wSYIoWtiWVdIKNZhxx91YCB6sFAXYQvkHiBUrHTfLhgMdTyHkasqK69qBxDm1r9qaacfdhXsvTIAzQJWQqEaM92Fw7HkrBZkrWldzpbHulO36kuIy1/QBBAcFNeNUOW5vYvKwCoEFjaVWXxkoc+xXuL3nx43tma/3shm/XlfV+HXbFBvbdQdVYzVnI5ITlnNI0xwfTGXw0+zY4mIGDp0YoWp2CudtV9SMGCZs6F3hK2G7U8/HMvDVEUfLxBktDB4VZ228cP0jfSjZgSptYjcphF8oGiF2qoeYxObdFarJVfmlB/ErE2Nx9Or7Fs+gNH0sD6dduNlvR4vhi6ym3OkZ3BfZIkKYl30qJfWrrq4brAmAMK7nu2C2xrNq/20Rfbc97vZp5Satg3xvCzBmQ3v4r+7evnWguS8RGTPQS4GAERw1d0WOC5afqDStBlm73DLONIN+/4dOLivGh6uxVnulPIPaxBqsmY40+t1txY3DPZhstzdH6G1zvCAkYEBPM2Ci/wNEJqCLwT0hvnRtZvhMKigkwwyyfLifsEwsPxojRyzz1ns8nwQr83a/HSV+Ck5SM0Oyb/Y1HB+IvXknOPVsUXymRCt7s9tDiOr6tlBQyvbmd1wrIF+CdRH43mvU8nyN3aB+91T7PpvG4kqadCS04k9Es2DzpG+nKe9rZfPftjbTVkITZs6j98Ma+C0N17HruNuRYRfss+AhDGFsLeJ4CfNztUrTRypwLwxDmq5ghC6XcbxYRFEYPrMnSTaEvS9+n3KzDBz3kpziLGnljFq91H02h8AVjYnOJrB+gKtvp6fY/he4MayX3O593LaUl84326C1N+bt2RJyKoln94vxvsdjbwZcns2F/l10vDQsWQZzPujBDOTvYyua4qjPm4u9SbE8zf+FMGb/wn8tt33m/LQWers/NDHQHt03o+iZ69B61xF1HU+7q4P7vr6kKa7n0gPgVprVZPa0X3ZNq0Yzrrsd/woE02qeuIUodBGKLQvIeW5A5HmW2XlulmWeQ3AxA4aPZ6Vp8/oB9t6wRV3rX1I5BJI='}, 'proxy': {'sha256': 'dad85948b773699c31ca6bc3f808da8d0bebc58d9c1b25220687d1823a3fa674', 'bytes': 2792, 'z64': 'eNqFVm1v4jgQ/s6vsPhwTqQQXvbaOwXxoerSa6VeQQur3btuFTmJA94mdtY2UKT78Te2kxYo0FQVY2c8L888nkm73f6XStFJSUUSVjC9RYVISYHm19Pu14e77yiRLFvQIeICzWa3iPDMiKmkGeWageYStgrGF2G73W6xshJSI6K2PGWiWf5UgjeyUK1cihJVRC8LlqB6ewrLRkXSRlKa6Fd5q1qtlrWMMpqjkjDu+VELwUOUotZ2uKB6xTLPH43cgtar/qD3+64qKQqPce0Voaogbc9/7D8F/UvQ7KFcSFQgxm1QHu5WUqRdRYu8a+JZKeyHkpIs1vQFDjoDgABVnm9d7DwsR+BBE6nVhoExD1+T6o4vIxwYaSrLWhrneS1dlUmEfd+ZqkY2Bsg9JHKxfhw8+UOlR5WxqWt3dUYVBKVEsaYm3coWSmnQiwEBk5WrnMM0nMV3f08+jz2nUYqM+r/1RG8wsBbTfDEyNQsLQTLlVS7dZKtNiv6QccUyOnoNqv80GmG3iXcj2lEwaHqNToCXQmns25DA1yM2BcZgpf/n4FN/14SkYb4qipLo1FRiKUra/bl57pIFsK8ru0ugbeeRJE+ddb9LUs3WtEsqFiqRPuPA2jYiBesNWA1/UsE5TbVncqMy2Eimqaz5ZKGnVI4eBKevO1puo9ZBdV1KEZwfkQ1hr9QPRUV5XPtggnu4P/gj7MFfv47L5bzPGFqok7ZWnL3sGjyS3F7om72tt7yrVVl5JEgCkQDEazq6IeDVjw6pi3ImgWpzuaLvXm2WrKDIvHp/zDwZ0aTJwZLHu7y4+HTpH1UGFA0vzZnj1mqlJEwJj22dYipyuPtJuLMaOn9JmEnbGU6aSiCg51OR1KBYaloATofk8LHonQvb5FU3mQQjHPT9x96TzdjciQT/NZ7jIMG346vP5ncynd9NHmbYP+3YVsDS1eUPRm7n82m3H/bRRe8TmkEGLKXoKydrwgqSFPSH/MGvBddwazr3lC/0MkK9erMmVITSQiiraf6xf9a/A7uO4iPEzQMqiqI3d2MphfTwDIBOxIsZKMRsI6YsNpSbsDODkXLpdAQvttAQlBaSfhBdSeQzXAHbO/fvSVgRaVoHht5NJSdFp1xp67lTlz7DZ02/awJHqZGZ8WOuredCCWA5ib99mTzc//Ofla+/jK/mThx/v7530sPkZnJ/P/kW9MRlr+d/6AcOOQbkGVCnSQldTe9Qk1bD6GyIEpI+w6AGDDWTtAQYQPy1AlmBAK0lhS8Ae8iUfwjGLSPA+PlI6EtKK41uoCeMX5jSytY2qqCHHz1XX1vP3Izz13a/DZpFDMPZazYWUF8qPdvRmjYeuJtlurIfuDdNb/eDPVDrsL3JzMYbNFbnrKRipd3mAWH9/axyBnAXB4SoL4XDzj8cGKY3NyQ30yUyG3vKb1Ol9da97TQ0Z45xmlrUd3zZisuDKWI/Q9wYce+9epoEJ0aJIcASvg323e1y086rM84O/JydgW5Cma+kOvzIWXSL0P6Y6lNj0YdPQcApjjkpaRzD90ccmw/COMZRE4JcmdtnOOW3/geiBTgl'}}
BASE=Path('/var/lib/agentenv-hpab-services-v1')
SESSION='relay-20261029-0d032371'
CONTROL='LittleFish-15/AgentENV-relay-control'
RESULTS='LittleFish-15/AgentENV-relay-results'
APPROVAL_PATH='root-approvals/'+SESSION+'/ab-full-host-dax-services-v1.json'
CREDS=Path('/home/jwk/.local/state/agentenv-github-relay/credentials.json')
NEW_SHA='59767d198966db908e662cfbe0f144b93d8fd20f01a39c917977aa9e8efd8a6a'
SDK_SHA='88686bc4e869c6442eb7d88128a2d3efd82468696c489734fc80b4692ac60223'
ADAPTER_SHA='34ed1c5666b5628cc37b4c75f95a44766b0cd119eb02f0df8c9ce15a54bcdfa0'
IMAGE_SHA='68e386f9ad745c7c9a19de5dad354e175b62b5a8296a53e559468d562c8addc5'
BYTES=1811939328
KERNEL='6.6.0-145.3.34.165.oe2403sp3.aarch64'
READERS=['hpab-reader-b-v1']
PORT=18231


def need(ok,reason):
    if not ok:raise RuntimeError(reason)


def wire(value):
    # The existing provider's manifest/config digest preserves JSON key order.
    return json.dumps(value,separators=(',',':'),ensure_ascii=False).encode()


def source(name):
    item=EMBEDDED[name];d=zlib.decompressobj()
    raw=d.decompress(base64.b64decode(item['z64'],validate=True),256*1024+1)
    need(len(raw)<=256*1024 and d.eof and not d.unused_data and not d.unconsumed_tail
         and hashlib.sha256(raw).hexdigest()==item['sha256'],'Embedded source differs')
    return raw


def module(name):
    m=types.ModuleType(name);m.__file__=str(BASE/(name+'.py'))
    exec(compile(source(name),m.__file__,'exec'),m.__dict__);return m


def identity():
    return {'hostname':platform.node(),'machineId':Path('/etc/machine-id').read_text().strip(),
        'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'kernel':platform.release(),'architecture':platform.machine(),'uid':1204,'gid':1205}


def read(path,limit=512*1024,owners=(0,1204)):
    path=Path(path);need(path.resolve(strict=True)==path,'Input path redirected')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as f:
        a=os.fstat(f.fileno());need(stat.S_ISREG(a.st_mode) and a.st_uid in owners and a.st_size<=limit,'Input owner/type/size differs')
        data=f.read(limit+1);b=os.fstat(f.fileno())
    sig=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
    need(len(data)<=limit and sig(a)==sig(b)==sig(path.stat()),'Input changed')
    return data


def digest(path):
    path=Path(path);need(path.resolve(strict=True)==path,'Hash source redirected')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    h=hashlib.sha256()
    with os.fdopen(fd,'rb') as f:
        a=os.fstat(f.fileno());need(stat.S_ISREG(a.st_mode) and a.st_size<=4*1024**3,'Hash source invalid')
        for block in iter(lambda:f.read(1024**2),b''):h.update(block)
        b=os.fstat(f.fileno())
    sig=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
    need(sig(a)==sig(b)==sig(path.stat()),'Source changed during hashing')
    return h.hexdigest()


def folder(p,uid=0,gid=0,mode=0o755):
    need(p.resolve()==p,'Directory redirected')
    if not p.exists():p.mkdir(mode=mode);os.chown(p,uid,gid);os.chmod(p,mode)
    s=p.stat();need(stat.S_ISDIR(s.st_mode) and s.st_uid==uid and not stat.S_IMODE(s.st_mode)&0o022,'Directory identity differs')


def put(p,raw,uid=0,gid=0,mode=0o644):
    need(p.parent.resolve()==p.parent and not p.is_symlink(),'Output redirected')
    if p.exists():
        s=p.stat();need(s.st_uid==uid and stat.S_IMODE(s.st_mode)==mode and read(p,len(raw)+1)==raw,'Prior output differs; preserved');return
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as f:
        os.fchown(f.fileno(),uid,gid);os.fchmod(f.fileno(),mode);f.write(raw);f.flush();os.fsync(f.fileno())


def tool(name):
    for prefix in ('/usr/sbin','/usr/bin','/sbin','/bin'):
        p=Path(prefix)/name
        if p.is_file():
            s=p.resolve().stat();need(s.st_uid==0 and not s.st_mode&0o022,'System tool is writable')
            return str(p)
    raise RuntimeError('Missing system tool: '+name)


def cmd(argv,seconds=60,owner=False,check=True,env=None):
    opts={'user':1204,'group':1205,'extra_groups':[grp.getgrnam('ubsmd').gr_gid],'umask':0o077} if owner else {}
    r=subprocess.run(list(map(str,argv)),stdin=subprocess.DEVNULL,capture_output=True,timeout=seconds,
        env=env or {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/home/jwk','LANG':'C','LC_ALL':'C'},**opts)
    need(not check or r.returncode==0,'Command failed: '+Path(str(argv[0])).name+' exit='+str(r.returncode))
    return r


def props(name):
    r=cmd([tool('systemctl'),'show',name,'--no-pager',
        '--property=MainPID,ActiveState,LoadState,Result,ExecMainStatus,Description,User,Group,ControlGroup'])
    return dict(line.split('=',1) for line in r.stdout.decode().splitlines() if '=' in line)


def ticks(pid):return Path('/proc',str(pid),'stat').read_text().rsplit(')',1)[1].split()[19]


def zero_caps(pid):
    return all(int(line.split()[1],16)==0 for line in Path('/proc',str(pid),'status').read_text().splitlines()
               if line.startswith(('CapInh:','CapPrm:','CapEff:','CapAmb:')))


def toml(value):
    import tomllib
    lines=[]
    def emit(row,prefix):
        if prefix:lines.append('['+'.'.join(prefix)+']')
        for key,v in row.items():
            need(re.fullmatch('[A-Za-z0-9_-]+',key) is not None,'Invalid TOML key')
            if not isinstance(v,dict):lines.append(key+' = '+json.dumps(v))
        lines.append('')
        for key,v in row.items():
            if isinstance(v,dict):emit(v,prefix+[key])
    emit(value,[]);raw=('\n'.join(lines)+'\n').encode()
    need(tomllib.loads(raw.decode())==value,'TOML serialization differs');return raw


class Start:
    def __init__(self,api,auth,control,result,node):
        self.api,self.auth,self.control,self.result,self.node=api,auth,control,result,node
        self.peer='node-b' if node=='node-a' else 'node-a'
        self.n=node[-1];self.entrySha=hashlib.sha256(read(Path(__file__),256*1024)).hexdigest()
        self.plan=json.loads(read(Path(auth['nodes'][node]['planPath'])))
        need(api.digest(api.encoded(self.plan))==auth['nodes'][node]['planSha256'],'Exported plan changed')
        need(self.plan['identity']==identity() and self.plan['logicalUbBytes']==BYTES and
             self.plan['maxPostMapCoverageBytes']==4294967296 and self.plan['normalFileFallbackAllowed'] is False,
             'Plan scope differs')
        self.work=Path(self.plan['workDirectory']);self.active=self.work/'active'
        self.path=BASE/'private/journal.json'
        self.state=api.load(self.path) if self.path.exists() else {'version':1,'node':node,'runId':auth['runId'],
            'identity':identity(),'entrySha256':self.entrySha,'steps':{},'units':{},'phase':'not_started',
            'SDK_called':False,'Guest_created':False,'logicalUbBytes':BYTES,'physicalHardQuota':False,
            'netSavingsBytes':None}
        need(self.state['runId']==auth['runId'] and self.state['identity']==identity() and
             self.state['entrySha256']==self.entrySha,'Prior transaction differs')

    def mark(self,phase):
        self.state['phase']=phase
        temporary=self.path.with_name('journal-'+secrets.token_hex(8)+'.next')
        put(temporary,wire(self.state)+b'\n',mode=0o600);os.replace(temporary,self.path)
        fd=os.open(self.path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
        print('PHASE='+self.node+':'+phase,flush=True)

    def once(self,label,fn):
        old=self.state['steps'].get(label)
        if old:
            need(old['state']=='done','Prior '+label+' outcome requires explicit reconciliation')
            return old['result']
        self.state['steps'][label]={'state':'intent'};self.mark(label+'_intent')
        value=fn();self.state['steps'][label]={'state':'done','result':value};self.mark(label+'_confirmed')
        return value

    def event(self,kind,value):
        payload=wire(value)
        r={'version':1,'node':self.node,'runId':self.auth['runId'],'identity':identity(),
           'entrySha256':self.entrySha,'kind':kind,'dataJson':payload.decode(),'dataSha256':self.api.digest(payload)}
        key='hpab-events/'+SESSION+'/'+self.auth['runId']+'/nobuild-v2/'+self.node+'/'+kind+'.json'
        self.result.immutable_result(RESULTS,1438089386,'main',key,self.api.encoded(r));return r

    def peer_event(self,kind,wait=0):
        key='hpab-events/'+SESSION+'/'+self.auth['runId']+'/nobuild-v2/'+self.peer+'/'+kind+'.json'
        end=time.monotonic()+wait
        while True:
            code,raw,_=self.result.contents(RESULTS,key,'main')
            if code==200:
                r=json.loads(raw)
                need(r['node']==self.peer and r['identity']==self.auth['nodes'][self.peer]['identity'] and
                    r['runId']==self.auth['runId'] and r['entrySha256']==self.entrySha and r['kind']==kind,
                    'Peer receipt binding differs')
                need(isinstance(r['dataJson'],str) and self.api.digest(r['dataJson'].encode())==r['dataSha256'],
                     'Peer payload bytes differ')
                r['data']=json.loads(r['dataJson']);return r
            need(code==404,'Peer result unavailable')
            if time.monotonic()>=end:return None
            print('WAIT_PEER='+self.peer+':'+kind,flush=True);time.sleep(10)

    def python(self,name,*args):
        bootstrap="import sys,runpy;sys.path.insert(0,sys.argv.pop(1));m=sys.argv.pop(1);sys.argv[0]=m;runpy.run_module(m,run_name='__main__')"
        return ['/usr/bin/python3','-I','-B','-c',bootstrap,str(BASE/'code'),name,*map(str,args)]

    def bound(self,label):
        row=self.state['units'][label];p=props(row['name'])
        need(row.get('pid') and p['ActiveState']=='active' and int(p['MainPID'])==row['pid'] and
            p['Description']==row['description'] and ticks(row['pid'])==row['ticks'],'Owned '+label+' process changed')
        return row

    def launch(self,label,argv,extra):
        name='aenv-hpab-'+self.n+'-'+label+'-'+self.auth['runId'][-8:]+'.service'
        need(props(name)['LoadState']=='not-found','New unit name already exists')
        row={'name':name,'description':'AgentENV Host DAX '+self.auth['runId']+' '+self.node+' '+label,
             'argvSha256':self.api.digest(self.api.encoded(argv)),'launchIntent':True}
        self.state['units'][label]=row;self.mark(label+'_unit_launch_intent')
        common=['Type=exec','Restart=no','UMask=0077','KillMode=control-group','TimeoutStopSec=90',
            'LimitNOFILE=65536','LimitCORE=0','StandardOutput=journal','StandardError=journal',
            'WorkingDirectory='+str(self.work),'Description='+row['description']]
        cmd([tool('systemd-run'),'--quiet','--unit='+name,*['--property='+x for x in common+extra],'--',*argv])
        p=props(name);need(p['ActiveState']=='active' and int(p['MainPID'])>0,'Unit start not confirmed')
        row.update(pid=int(p['MainPID']),ticks=ticks(int(p['MainPID'])));self.mark(label+'_unit_started')
        return row

    def ready(self,label,path,key,value,seconds=1200):
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            self.bound(label)
            if path.exists():
                r=json.loads(read(path))
                if r.get(key)==value:return r
                need(r.get(key) not in ('unresolved_preserved','stopped_preserve_resources',
                      'rootfs_stopped_preserve_resources','unresolved_create'),'Helper reported preserved failure')
            time.sleep(1)
        raise RuntimeError('Helper readiness not confirmed; preserve, never relaunch SDK')

    def export_code(self):
        manifest_raw=read(self.work/'provider-source-manifest.json')
        need(self.api.digest(manifest_raw)==self.plan['providerManifestSha256'],'Provider manifest changed')
        manifest=json.loads(manifest_raw)
        folder(BASE/'code');folder(BASE/'code/aenv_ub_provider')
        for rel,pin in manifest.items():
            need(re.fullmatch(r'(aenv_ub_provider|tests)/[A-Za-z0-9_]+\.py',rel) is not None,'Invalid source member')
            data=read(self.work/'provider-code'/rel,256*1024)
            need(self.api.digest(data)==pin,'Provider source changed')
            if rel.startswith('aenv_ub_provider/'):put(BASE/'code'/rel,data)
        adapter=Path('/home/jwk/agent/r')/('lazy4-'+self.n+'-v1')/'libaenv-ub.so'
        need(digest(adapter)==ADAPTER_SHA,'Adapter changed')
        put(BASE/'public/libaenv-ub.so',read(adapter,1024**2),gid=1205,mode=0o640)
        for row in list(self.plan['binaries'].values())+list(self.plan['dependencies'].values()):
            need(digest(row['path'])==row['sha256'],'Runtime/dependency changed')
        folder(self.active,1204,1205,0o700)
        for name in ('state','logs','config','cache','tmp','deps','fc','run','cli','cli/aenv'):
            folder(self.active/name,1204,1205,0o700)
        return {'providerManifestSha256':self.plan['providerManifestSha256']}

    def lookup_old(self):
        names=self.auth['priorObjectNames']
        need(0<len(names)<=32 and all(re.fullmatch(r'aenv_[0-9a-f]{32}',s) for s in names),'Prior object set invalid')
        put(BASE/'public/sdk_lookup.py',source('sdk_lookup_python'))
        r=cmd(['/usr/bin/python3','-I','-B',BASE/'public/sdk_lookup.py',*names],60,owner=True,check=False)
        value=json.loads(r.stdout)
        self.state['oldObjectLookup']=value;self.mark('old_object_lookup_observed')
        need(r.returncode==0 and value['initializeRc']==0 and value['finalizeRc']==0 and value['allAbsent'] is True,
             'Old named object still exists or lookup unknown; no deletion or new allocation')
        return value

    def maintenance(self):
        m=module('maintenance')
        s=m.service();pid=int(s['MainPID'])
        need(s['ActiveState']=='active' and pid==self.auth['nodes'][self.node]['ubsePid'],'UBSE changed since review')
        def process(p):
            q=Path('/proc',str(p));fields=dict(l.split(':',1) for l in (q/'status').read_text().splitlines() if ':' in l)
            need([int(x) for x in fields['Uid'].split()]==[pwd.getpwnam('ubse').pw_uid]*4 and
                 '/system.slice/ubse.service' in (q/'cgroup').read_text(),'UBSE identity differs')
            return {'pid':p,'ticks':ticks(p)}
        m.process=process
        candidate=self.auth['nodes'][self.node]['candidatePath']
        current_params={p.name:p.read_text().strip() for p in Path('/sys/module/obmm/parameters').iterdir()}
        need(set(current_params)==set(m.PARAMS),'Unknown original OBMM parameters; review required')
        m.PARAMS=current_params
        need(Path('/proc/sys/kernel/tainted').read_text().strip()==self.auth['nodes'][self.node]['taintBefore'],
             'Kernel taint changed since review; no module operation')
        m.configure({'node':platform.node(),'bootId':identity()['bootId'],'candidateFile':candidate,
            'stage':'/var/lib/agentenv-hpab-module-v1','ubseProcess':process(pid),
            'taintBefore':Path('/proc/sys/kernel/tainted').read_text().strip()})
        m.APPROVAL='AB_FULL_HOST_DAX_SERVICES_V1'
        need(digest(candidate)==NEW_SHA,'Candidate module changed')
        original=m.Local({});original.check_old()
        old=list(sys.argv)
        try:
            sys.argv=['maintenance','activate','--approval',m.APPROVAL]
            rc=m.main()
        finally:sys.argv=old
        need(rc in (None,0),'Module maintenance did not complete')
        report=json.loads(read(m.STAGE/'journal.json'))
        need(report['phase']=='candidate_loaded_ubse_active','Candidate/UBSE not confirmed')
        return report

    def candidate_live(self):
        need(Path('/sys/module/obmm/srcversion').read_text().strip()=='C2BBB64D75C618180ABA3A6' and
            Path('/sys/module/obmm/parameters/pmem_ro_enable').read_text().strip()=='Y','Candidate context changed')
        row=self.state['steps']['maintenance']['result']['currentProcess']
        need(props('ubse.service')['MainPID']==str(row['pid']) and ticks(row['pid'])==row['ticks'],'UBSE changed')

    def permissions(self):
        acl=[]
        for name in ('obmm','ublk-control'):
            path=Path('/dev')/name;s=path.stat()
            old=cmd([tool('getfacl'),'-p',str(path)]).stdout
            backup=BASE/'private'/(name+'.acl');put(backup,old,mode=0o600)
            row={'path':str(path),'inode':s.st_ino,'rdev':s.st_rdev,'backup':str(backup),
                 'beforeSha256':self.api.digest(old)}
            acl.append(row);self.state['acl']=acl;self.mark('device_acl_intent')
            cmd([tool('setfacl'),'-m','u:1204:rw',str(path)])
            row['appliedSha256']=self.api.digest(cmd([tool('getfacl'),'-p',str(path)]).stdout)
            self.mark('device_acl_applied')
        return {'acl':acl,'udevRuleInstalled':False}

    def sdk(self,publication=None):
        self.candidate_live();owner=self.active/'provider'
        need(not owner.exists(),'Prior SDK intent exists; never allocate/import twice')
        cfg={'version':1,'mode':'pmem','role':'publish' if self.node=='node-a' else 'import',
            'workDir':str(owner),'adapter':str(BASE/'public/libaenv-ub.so'),'adapterSha256':'sha256:'+ADAPTER_SHA,
            'region':'default','logicalBudgetBytes':BYTES,'maxCoverageBytes':4294967296,
            'hostPmemReleaseReceipt':str(BASE/'public/local-release.json')}
        if self.node=='node-a':
            image=self.plan['image'];need(image['sha256']==IMAGE_SHA and image['bytes']==BYTES,'Container identity differs')
            source_spec={'objectId':'image-'+IMAGE_SHA,'generation':IMAGE_SHA[:32],
                'sha256':'sha256:'+IMAGE_SHA,'bytes':BYTES,'socket':str(owner/'data.sock')}
            put(BASE/'public/catalog.json',self.api.encoded({'version':1,'objects':[{'path':image['path'],'backing':source_spec}]}))
            cfg.update(readers=READERS,catalog=str(BASE/'public/catalog.json'),
                       hostPmemReaderEpochs={READERS[0]:self.auth['nodes']['node-b']['readerEpoch']})
        else:
            need(publication['mode']=='pmem' and publication['readers']==READERS and len(publication['replicas'])==1,
                 'Peer publication shape differs')
            put(BASE/'public/publisher.json',wire(publication))
            cfg.update(readerId=READERS[0],manifest=str(BASE/'public/publisher.json'))
        put(BASE/'public/sdk-config.json',self.api.encoded(cfg))
        self.state['SDK_called']=None;self.mark('sdk_start_intent')
        self.launch('sdk',self.python('aenv_ub_provider','serve',BASE/'public/sdk-config.json','--run'),
            ['User=1204','Group=1205','SupplementaryGroups=ubsmd','NoNewPrivileges=yes',
             'CapabilityBoundingSet=','AmbientCapabilities=','LimitMEMLOCK=4294967296','MemoryMax=6G'])
        record=self.ready('sdk',owner/'owner.json','state','serving')
        observed=json.loads(read(owner/'replicas.json'))
        need(observed['mode']=='pmem' and observed['readers']==READERS and len(observed['replicas'])==1 and
            observed['replicas'][0]['identity']['sha256']=='sha256:'+IMAGE_SHA and
            observed['replicas'][0]['identity']['bytes']==BYTES,'SDK published identity differs')
        need(publication is None or observed==publication,'Importer publication differs')
        need(zero_caps(self.bound('sdk')['pid']),'SDK owner capabilities differ')
        self.state['SDK_called']=True
        return {'publication':observed,'ownerJournal':record,'process':self.bound('sdk')}

    def view(self):
        from aenv_ub_provider import host_pmem_rootfs,stored,contract
        sdk=self.state['steps']['sdk']['result'];publication=sdk['publication'];owner=self.bound('sdk')
        source_spec={**publication['replicas'][0]['identity'],'socket':str(self.active/'provider/data.sock')}
        files=[]
        for f in self.plan['layers']:
            if f['kind']!='rootfs':continue
            files.append({'name':f['digest'][7:]+'.commit','replica':{
                'brokerSocket':str(self.active/'lower.sock'),'objectName':'aenv_'+secrets.token_hex(16),
                'generation':secrets.token_hex(16),'layerDigest':f['digest'],'fileBytes':f['bytes'],
                'mappingBytes':((f['bytes']+stored.HEADER_BYTES+stored.ALIGN-1)//stored.ALIGN)*stored.ALIGN,
                'allowRepositoryFallback':False}})
        cfg={'version':1,'workDir':str(BASE/'view'),'source':source_spec,'ownerUid':1204,
            'ownerPid':owner['pid'],'ownerStartTicks':owner['ticks'],'publication':publication,
            'releaseReceipt':str(BASE/'public/local-release.json'),'kernelRelease':KERNEL,
            'moduleSrcversion':'C2BBB64D75C618180ABA3A6','files':files,'brokerSocket':str(self.active/'lower.sock'),
            'brokerGid':1205,'runtimeIndex':str(BASE/'public/rootfs-index.json'),'payloadResponses':2}
        plan=host_pmem_rootfs.plan(cfg);put(BASE/'private/rootfs-config.json',contract.canonical(cfg),mode=0o600)
        self.state['viewConfigSha256']=plan['configSha256'];self.mark('rootfs_view_intent')
        self.launch('view',self.python('aenv_ub_provider.host_pmem_rootfs','serve','--config',BASE/'private/rootfs-config.json',
            '--expected-config-sha256',plan['configSha256'],'--approval','CREATE_READONLY_ROOTFS_HOST_PMEM'),
            ['PrivateMounts=yes','CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SETUID CAP_SETGID CAP_DAC_READ_SEARCH','MemoryMax=6G'])
        record=self.ready('view',BASE/'view/host-pmem-session.json','phase','rootfs_broker_ready')
        evidence=record.get('rootfsBroker',{}).get('fileEvidence',[])
        need(len(evidence)==8 and all(x['activeDax'] and x['readonlyMount'] for x in evidence),
             'Actual DAX file binding not confirmed')
        index=json.loads(read(BASE/'public/rootfs-index.json'))
        need(len(index['replicas'])==8 and all(x['allowRepositoryFallback'] is False for x in index['replicas']),
             'Required DAX runtime index differs')
        return {'configSha256':plan['configSha256'],'journal':record,'indexSha256':digest(BASE/'public/rootfs-index.json')}

    def runtime(self):
        self.candidate_live();self.bound('sdk');self.bound('view')
        source_base=Path(self.plan['sourceDeployment']);deps=self.active/'deps'
        # Reuse dependency payloads; only small configs are independently copied.
        # No rootfs/memory lower payload is copied or linked here.
        count=total=0
        for p in sorted((source_base/'deps').rglob('*')):
            need(p.resolve(strict=True)==p,'Dependency symlink refused')
            relative=p.relative_to(source_base/'deps');dest=deps/relative
            if p.is_dir():folder(dest,1204,1205,0o700);continue
            s=p.stat();need(stat.S_ISREG(s.st_mode) and s.st_uid==1204,'Unexpected dependency owner/type')
            count+=1;total+=s.st_size;need(count<=2048 and total<=3*1024**3,'Dependency budget exceeded')
            if str(relative)=='overlaybd/etc/overlaybd/overlaybd.json':continue
            need(not dest.exists(),'Dependency export already exists; preserve partial runtime')
            if p.suffix=='.json':put(dest,read(p,2*1024**2),1204,1205,0o600)
            else:os.link(p,dest)
        overlay=deps/'overlaybd/etc/overlaybd'
        for p in (deps/'overlaybd',deps/'overlaybd/etc',overlay):folder(p,1204,1205,0o700)
        clean={'logConfig':{'logLevel':1,'logPath':str(self.active/'logs/overlaybd.log')},
            'cacheConfig':{'cacheType':'file','cacheDir':str(self.active/'state/overlaybd-cache'),
                           'cacheSizeGB':1,'refillSize':262144,'blockSize':65536},
            'credentialFilePath':'','credentialConfig':{},'ioEngine':0,
            'p2pConfig':{'enable':False},'enableAudit':False,'registryFsVersion':'v2'}
        put(overlay/'overlaybd.json',json.dumps(clean).encode(),1204,1205,0o600)
        cfg={'home_path':str(self.active/'state'),'runtime_path':str(self.active/'run'),
            'deps_path':str(deps),'virtualization_mode':'kvm',
            'firecracker':{'binary_path':str(deps/'firecracker/1.15.1-patch-v3/firecracker'),
                'work_dir':str(self.active/'fc'),'serial_dir':str(self.active/'logs'),'log_level':'Info'},
            'kernel':{'image_path':str(deps/'kernel/vmlinux-6.1.175/vmlinux.bin')},
            'tools':{'version':'0.1.1','drive_path':str(deps/'tools/0.1.1/tools.ext4')},
            'snapshot':{'repository_backend':'posix_fs','p2p_enabled':False,
                'ub_rootfs_index':str(BASE/'public/rootfs-index.json'),
                'ub_rootfs_index_sha256':self.state['steps']['view']['result']['indexSha256']},
            'backend':{'posix_fs':{'snapshot_store':str(self.work/'seed')}},
            'ublk':{'daemon_binary_path':self.plan['binaries']['bin/uvm-ublk-daemon']['path'],
                'daemon_socket_path':str(self.active/'run/ublk.sock'),'daemon_log_path':str(self.active/'logs/ublk.log'),
                'daemon_metrics_listen_addr':''},'image':{'cache':{'gc':{'enabled':False}}},'p2p':{'enabled':False},
            'pool':{'network':{'maintenance_enabled':False},'block':{'enabled':False,'startup_prewarm':False},
                    'firecracker':{'enabled':False,'startup_prewarm':False}},'observability':{'enabled':False},
            'node_identity':{'node_id':'host-dax-'+self.n,'cluster_id':self.auth['runId'],
                             'service_instance_id':'hpab-'+self.n+'-runtime'}}
        # Check actual Linux sun_path budget, not only the path prefix.
        need(len(os.fsencode(self.active/'fc/agentenv-fc-XXXXXX/firecracker.socket'))<=107,'FC socket budget exceeded')
        put(BASE/'public/runtime.toml',toml(cfg))
        key='e2b_'+secrets.token_hex(24)
        put(self.active/'cli/aenv/credentials',('url = "http://127.0.0.1:18231"\napi_key = '+json.dumps(key)+'\n').encode(),1204,1205,0o600)
        put(BASE/'private/runtime.env',('AENV_API_KEY='+key+'\nAPI_ADDR=127.0.0.1:18231\n'
            'AENV_CONFIG_PATH='+str(BASE/'public/runtime.toml')+'\n'
            'HOME=/home/jwk\nAENV_HOME_PATH='+str(self.active/'state')+'\n'
            'AENV_DEPS_PATH='+str(deps)+'\nAENV_RUNTIME_PATH='+str(self.active/'run')+'\n'
            'PATH='+str(source_base/'native/bin')+':/usr/sbin:/usr/bin:/sbin:/bin\n'
            'LD_LIBRARY_PATH='+str(source_base/'native/lib')+':'+str(source_base/'native/fallback/lib')+'\n'
            'XTABLES_LIBDIR='+str(source_base/'native/xtables')+'\n'
            'TMPDIR='+str(self.active/'tmp')+'\nXDG_CACHE_HOME='+str(self.active/'cache')+'\n').encode(),mode=0o600)
        before=os.stat('/proc/self/ns/net').st_ino
        prestart=('import os\nfrom pathlib import Path\nassert os.geteuid()==0\n'
            'assert os.stat("/proc/self/ns/net").st_ino != '+str(before)+'\n'
            'Path("/proc/sys/net/ipv4/ip_forward").write_text("1\\n")\n').encode()
        put(BASE/'public/runtime-prestart.py',prestart)
        server=self.plan['binaries']['bin/server']['path']
        row=self.launch('runtime',[server],['User=1204','Group=1205','SupplementaryGroups=ubsmd kvm',
            'AmbientCapabilities=CAP_SYS_ADMIN CAP_NET_ADMIN','CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN',
            'PrivateNetwork=yes','PrivateMounts=yes','EnvironmentFile='+str(BASE/'private/runtime.env'),
            'ExecStartPre=+/usr/bin/python3 -I -B '+str(BASE/'public/runtime-prestart.py'),
            'BindReadOnlyPaths='+self.plan['sourceManagedLayers']+':'+self.plan['privateReadonlyBindTarget']+' '+
                str(self.work/'seed/repository/catalog')+' '+str(self.work/'seed/repository/snapshots')])
        end=time.monotonic()+90
        while time.monotonic()<end:
            self.bound('runtime')
            check=cmd([tool('nsenter'),'-t',str(row['pid']),'-n','--',tool('curl'),'-sS','--max-time','3',
                '-o','/dev/null','-w','%{http_code}','http://127.0.0.1:18231/health'],10,check=False)
            if check.returncode==0 and check.stdout==b'204':break
            time.sleep(1)
        else:raise RuntimeError('Runtime health not confirmed; backing retained')
        return {'unit':row,'health':204,'configSha256':digest(BASE/'public/runtime.toml'),
                'binarySha256':self.plan['binaries']['bin/server']['sha256'],
                'privateNetwork':True,'HostForwardingChanged':False}

    def proxies(self):
        rt=self.bound('runtime')
        config={'port':PORT,'socket':str(self.active/'api.sock')}
        put(BASE/'public/proxy.json',self.api.encoded(config));put(BASE/'public/proxy.py',source('proxy'))
        common=['User=1204','Group=1205','NoNewPrivileges=yes','CapabilityBoundingSet=','AmbientCapabilities=']
        self.launch('inside-proxy',['/usr/bin/python3','-I','-B',str(BASE/'public/proxy.py'),'inside',str(BASE/'public/proxy.json')],
            common+['PrivateNetwork=yes','JoinsNamespaceOf='+rt['name']])
        end=time.monotonic()+15
        while not (self.active/'api.sock').exists() and time.monotonic()<end:
            self.bound('inside-proxy');time.sleep(.2)
        need((self.active/'api.sock').exists(),'Inside API proxy socket not ready')
        self.launch('host-proxy',['/usr/bin/python3','-I','-B',str(BASE/'public/proxy.py'),'host',str(BASE/'public/proxy.json')],common)
        end=time.monotonic()+20
        while time.monotonic()<end:
            self.bound('host-proxy');self.bound('inside-proxy')
            try:
                c=http.client.HTTPConnection('127.0.0.1',PORT,timeout=3);c.request('GET','/health')
                r=c.getresponse();body=r.read(4096);c.close()
                if r.status==204 and body==b'':break
            except OSError:pass
            time.sleep(.5)
        else:raise RuntimeError('Host API proxy health not confirmed')
        need(zero_caps(self.bound('host-proxy')['pid']) and zero_caps(self.bound('inside-proxy')['pid']),
             'API proxy capabilities differ')
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/home/jwk','LANG':'C','LC_ALL':'C',
             'LD_LIBRARY_PATH':str(Path(self.plan['sourceDeployment'])/'native/lib')+':'+
                               str(Path(self.plan['sourceDeployment'])/'native/fallback/lib'),
             'XDG_CONFIG_HOME':str(self.active/'cli')}
        check=cmd([self.plan['binaries']['bin/aenv']['path'],'list','--output','json'],30,owner=True,env=env)
        need(json.loads(check.stdout)==[],'New Runtime is not empty; preserve consumers')
        wrapper=('#!/bin/sh\nexport HOME=/home/jwk\nexport XDG_CONFIG_HOME='+str(self.active/'cli')+'\n'
            'export LD_LIBRARY_PATH='+str(Path(self.plan['sourceDeployment'])/'native/lib')+':'+
            str(Path(self.plan['sourceDeployment'])/'native/fallback/lib')+'\n'
            'exec '+self.plan['binaries']['bin/aenv']['path']+' "$@"\n').encode()
        put(self.active/'aenv-host-dax',wrapper,1204,1205,0o700)
        return {'api':'http://127.0.0.1:18231','health':204,'CLI':str(self.active/'aenv-host-dax'),
                'initialSandboxCount':0,'Guest_created':False,'guestCreationEnabled':False}

    def start(self):
        need(not self.state.get('terminal'),'This generation was stopped/cancelled; never restart or reallocate')
        self.once('export_code',self.export_code)
        sys.path.insert(0,str(BASE/'code'))
        self.once('lookup_old',self.lookup_old)
        self.event('old-objects-absent',self.state['steps']['lookup_old']['result'])
        peer=self.peer_event('old-objects-absent',wait=600)
        need(peer is not None and peer['data']['allAbsent'] is True,'Wait for peer lookup before any module change')
        self.once('maintenance',self.maintenance);self.candidate_live()
        self.once('permissions',self.permissions)
        self.event('module-ready',{'module':self.state['steps']['maintenance']['result'],'planSha256':self.auth['nodes'][self.node]['planSha256']})
        peer=self.peer_event('module-ready',wait=600)
        need(peer is not None,'Both modules must be ready before SDK publication')
        if self.node=='node-a':
            self.once('sdk',lambda:self.sdk())
            self.event('publication',self.state['steps']['sdk']['result']['publication'])
        else:
            peer=self.peer_event('publication',wait=1800)
            need(peer is not None,'A publication not confirmed; importer not attempted')
            self.once('sdk',lambda:self.sdk(peer['data']))
        self.bound('sdk');self.once('view',self.view);self.bound('view')
        self.once('runtime',self.runtime);self.bound('runtime')
        self.once('proxies',self.proxies)
        for label in ('sdk','view','runtime','inside-proxy','host-proxy'):self.bound(label)
        report={'status':'HOST_DAX_LOCAL_SERVICES_HEALTHY_HELD','node':self.node,
            'identity':identity(),'runtime':self.state['steps']['runtime']['result'],
            'access':self.state['steps']['proxies']['result'],'view':self.state['steps']['view']['result'],
            'SDK_called':True,'Guest_created':False,'logicalUbBytes':BYTES,'maxPostMapCoverageBytes':4294967296,
            'physicalHardQuota':False,'netSavingsBytes':None,'twoNodeGuestAccepted':False,
            'sharedObjectName':self.state['steps']['sdk']['result']['publication']['replicas'][0]['objectName']}
        self.state['report']=report;self.mark('services_healthy_held');self.event('services-ready',report)
        peer=self.peer_event('services-ready',wait=180)
        report=dict(report,peerServicesReady=peer is not None)
        self.api.atomic(BASE/'private/service-report.json',report)
        print(json.dumps(report,indent=2))

    def stop_unit(self,label):
        row=self.state['units'].get(label)
        if not row or row.get('stopped'):return
        self.bound(label);self.mark(label+'_stop_intent');cmd([tool('systemctl'),'stop',row['name']],120)
        p=props(row['name']);need(p['MainPID']=='0' and p['ActiveState']=='inactive','Unit exit not confirmed')
        row['stopped']=True;self.mark(label+'_stopped')

    def stop(self):
        sys.path.insert(0,str(BASE/'code'))
        # After external API use, a separate consumer reconciliation is required.
        need(not (self.active/'external-mutation-observed').exists(),
             'External sandbox mutation observed; reconcile consumers before retiring backing')
        if 'runtime' in self.state['units'] and not self.state['units']['runtime'].get('stopped'):
            need('proxies' in self.state['steps'] and self.state['steps']['proxies']['state']=='done',
                 'Runtime acceptance incomplete; consumer outcome requires explicit inspection')
            base=Path(self.plan['sourceDeployment'])
            env={'HOME':'/home/jwk','PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C',
                'XDG_CONFIG_HOME':str(self.active/'cli'),
                'LD_LIBRARY_PATH':str(base/'native/lib')+':'+str(base/'native/fallback/lib')}
            r=cmd([self.plan['binaries']['bin/aenv']['path'],'list','--output','json'],30,owner=True,env=env)
            need(json.loads(r.stdout)==[],'Runtime inventory is not confirmed empty')
        self.state['terminal']=True;self.mark('explicit_stop_generation_terminal')
        for label in ('host-proxy','inside-proxy','runtime'):self.stop_unit(label)
        if self.node=='node-a' and 'sdk' not in self.state['steps'] and 'sdk' not in self.state['units']:
            code,_,_=self.result.contents(RESULTS,'hpab-events/'+SESSION+'/'+self.auth['runId']+'/nobuild-v2/'+self.node+'/publication.json','main')
            need(code==404 and not (self.active/'provider').exists(),'Unconfirmed publication prevents cancellation')
            self.state['publicationNotAttempted']=True;self.mark('publisher_cancelled_without_sdk_attempt')
            self.event('publication-cancelled',{'publicationAttempted':False,'terminal':True})
            return
        if self.node=='node-b' and 'sdk' not in self.state['steps'] and 'sdk' not in self.state['units']:
            cancelled=self.peer_event('publication-cancelled')
            if cancelled is not None:
                need(cancelled['data']=={'publicationAttempted':False,'terminal':True},'Publisher cancellation differs')
                self.state['publicationNotAttempted']=True;self.mark('importer_cancelled_no_publication');return
            peer=self.peer_event('publication')
            need(peer is not None and not (self.active/'provider').exists(),'Publisher outcome unknown; preserve reader state')
            from aenv_ub_provider import contract
            manifest=peer['data']
            cancelled={'version':1,'scope':'host-pmem-reader-cancel','state':'not_imported',
                'ownerId':manifest['ownerId'],'manifestSha256':'sha256:'+hashlib.sha256(contract.canonical(manifest)).hexdigest(),
                'readerId':READERS[0],'epoch':self.auth['nodes']['node-b']['readerEpoch'],
                'sdkImportAttempted':False,'terminal':True}
            self.event('reader-released',cancelled);self.mark('reader_terminal_not_imported');return
        if 'view' in self.state['units'] and not self.state.get('viewReleased'):
            from aenv_ub_provider import host_pmem_cli
            cfg=json.loads(read(BASE/'private/rootfs-config.json'))
            need(not self.state.get('viewRetirePending'),'Prior DAX retirement reply unknown; preserve')
            self.state['viewRetirePending']=True;self.mark('view_retire_intent')
            result=host_pmem_cli.request_action(cfg,self.state['viewConfigSha256'],'retire')
            need(result['state']=='local_resources_released','DAX retirement not acknowledged')
            self.state.update(viewReleased=True,viewRetirePending=False);self.mark('view_released')
        elif 'view' not in self.state['steps'] and 'sdk' in self.state['units'] and not self.state.get('viewReleased'):
            from aenv_ub_provider import host_pmem_guard
            sdk=self.state['steps']['sdk']['result'];publication=sdk['publication'];owner=self.bound('sdk')
            source_spec={**publication['replicas'][0]['identity'],'socket':str(self.active/'provider/data.sock')}
            receipt={'version':1,'scope':'local-host-pmem','state':'released',
                'publication':host_pmem_guard.publication_binding(publication,source_spec),'source':source_spec,
                'bootId':identity()['bootId'],'ownerUid':1204,'ownerPid':owner['pid'],'ownerStartTicks':owner['ticks'],
                'volumeCreated':False,'creationOutcome':'not_attempted','volumeUuid':None,'volumeId':None,
                'mountAbsent':True,'localVolumeAbsent':True,'sharedBackingReleaseAuthorized':False}
            put(BASE/'public/local-release.json',wire(receipt)+b'\n')
            self.state['viewReleased']=True;self.mark('view_never_attempted_local_receipt_written')
        # An attempted but unconfirmed view is never replaced by a fabricated release.
        if 'sdk' in self.state['units'] and not self.state.get('sdkReleased'):
            need(self.state.get('viewReleased') is True,'No complete local DAX retirement; preserve SDK')
            argv=self.python('aenv_ub_provider','retire',self.active/'provider')
            if self.node=='node-a':
                peer=self.peer_event('reader-released',wait=0)
                need(peer is not None,'B importer release required before global deletion')
                put(BASE/'public/peer-release.json',wire(peer['data']))
                argv+=['--peer-receipt',str(BASE/'public/peer-release.json')]
            need(not self.state.get('sdkRetirePending'),'Prior SDK retirement reply unknown; preserve')
            self.state['sdkRetirePending']=True;self.mark('sdk_retire_intent')
            result=cmd(argv,600,owner=True,check=False)
            need(result.returncode==0 and json.loads(result.stdout)['state']=='released','SDK release not confirmed')
            journal=json.loads(read(self.active/'provider/owner.json'))
            need(journal['state']=='released' and journal.get('finalize_acknowledged') is True,'SDK journal incomplete')
            self.state.update(sdkReleased=True,sdkRetirePending=False);self.mark('sdk_released')
            for label in ('view','sdk'):
                if label not in self.state['units']:continue
                end=time.monotonic()+30
                while time.monotonic()<end:
                    p=props(self.state['units'][label]['name'])
                    if p['MainPID']=='0' and p['ActiveState']=='inactive':
                        self.state['units'][label]['stopped']=True;self.mark(label+'_exit_confirmed');break
                    time.sleep(.5)
                else:raise RuntimeError('Released helper exit unconfirmed; preserve module')
            if self.node=='node-b':self.event('reader-released',json.loads(read(self.active/'provider/release.json')))
            else:
                need(all(x.get('delete_acknowledged') and x.get('creation_confirmed') for x in journal['objects']) and
                     journal.get('base_post_sha256_verified') is True,'Global deletion/base integrity not confirmed')
                self.event('global-released',{'globalObjectDeleteAcknowledged':True,
                    'ownerId':self.state['steps']['sdk']['result']['publication']['ownerId']})
        self.mark('local_backing_released')

    def restore(self):
        # Both nodes must have a root-received A global-release ACK, even if B
        # never imported: A's publication may have used B's physical pool.
        if self.node=='node-a':
            need(self.state.get('sdkReleased') is True or self.state.get('publicationNotAttempted') is True,
                 'Global release or never-published cancellation not confirmed')
        else:
            peer=self.peer_event('global-released',wait=0)
            cancelled=self.peer_event('publication-cancelled',wait=0) if peer is None else None
            need(peer is not None and peer['data']['globalObjectDeleteAcknowledged'] is True or
                 cancelled is not None and cancelled['data']=={'publicationAttempted':False,'terminal':True},
                 'A global release or never-published cancellation ACK required')
        for label,row in self.state['units'].items():
            p=props(row['name'])
            need(p['MainPID']=='0' and p['ActiveState']=='inactive','An owned service still runs; no module restoration')
        need(not list(Path('/dev').glob('obmm_shmdev*')),'OBMM region remains; no restoration')
        stage=Path('/var/lib/agentenv-hpab-module-v1')
        if not stage.exists():
            need(Path('/sys/module/obmm/srcversion').read_text().strip()=='B2D1EBF7E6C2BB3EF877E36',
                 'Module changed without an owned maintenance journal; preserve')
            self.mark('original_module_unchanged_no_restore_needed');return
        for a in self.state.get('acl',[]):
            p=Path(a['path']);s=p.stat();need(s.st_ino==a['inode'] and s.st_rdev==a['rdev'],'Device identity changed')
            now=cmd([tool('getfacl'),'-p',str(p)]).stdout
            if self.api.digest(now)!=a['beforeSha256']:
                need(self.api.digest(now)==a['appliedSha256'],'ACL changed externally; preserve it')
                cmd([tool('setfacl'),'--restore='+a['backup']])
        r=self.state.get('rule')
        if r:
            p=Path(r['path']);need(digest(p)==r['sha256'] and p.stat().st_uid==0,'udev rule changed')
            p.unlink();cmd([tool('udevadm'),'control','--reload-rules'])
        m=module('maintenance');m.NODE=platform.node();m.BOOT=identity()['bootId']
        m.STAGE=Path('/var/lib/agentenv-hpab-module-v1');m.APPROVAL='AB_FULL_HOST_DAX_SERVICES_V1'
        module_journal=json.loads(read(stage/'journal.json'))
        need(module_journal['node']==platform.node() and module_journal['bootId']==identity()['bootId'] and
             module_journal['candidateSha256']==NEW_SHA,'Module recovery journal differs')
        m.PARAMS=module_journal['originalParameters']
        def process(p):
            q=Path('/proc',str(p));f=dict(x.split(':',1) for x in (q/'status').read_text().splitlines() if ':' in x)
            need([int(x) for x in f['Uid'].split()]==[pwd.getpwnam('ubse').pw_uid]*4 and
                 '/system.slice/ubse.service' in (q/'cgroup').read_text(),'UBSE restore identity differs')
            return {'pid':p,'ticks':ticks(p)}
        m.process=process;old=list(sys.argv)
        try:sys.argv=['maintenance','restore','--approval',m.APPROVAL];rc=m.main()
        finally:sys.argv=old
        need(rc in (None,0),'Original module restoration not confirmed');self.mark('original_module_restored')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('action',choices=('install-start','upgrade-start','start','status','stop','restore'),nargs='?',default='start')
    args=parser.parse_args()
    need(platform.system()=='Linux' and os.getuid()==os.geteuid()==0 and platform.release()==KERNEL,'Expected A/B matching-kernel root')
    node={'server1':'node-a','agent1':'node-b'}.get(platform.node());need(node is not None,'Not A/B')
    api=module('api');os.umask(0o077)
    tokens=json.loads(read(CREDS,8192,owners=(1204,)))
    s=CREDS.stat();need(not s.st_mode&0o077 and set(tokens)=={'controlToken','resultToken'},'Private token file differs')
    control,result=api.GitHub(tokens['controlToken']),api.GitHub(tokens['resultToken'])
    control.private_repo(CONTROL,1438089258);result.private_repo(RESULTS,1438089386)
    code,raw,_=control.contents(CONTROL,APPROVAL_PATH,'main');need(code==200,'No explicit root approval published')
    auth=json.loads(raw);pin=hashlib.sha256(read(Path(__file__),256*1024)).hexdigest()
    need(auth['schema']==1 and auth['humanApproved'] is True and auth['entrySha256']==pin and
         auth['scope']=='AB_FULL_HOST_DAX_SERVICES_V1' and auth['nodes'][node]['identity']==identity(),
         'Exact code/boot/root approval differs')
    if args.action in ('install-start','upgrade-start','start'):
        need(api.timestamp(auth['notBefore'])<=time.time()<api.timestamp(auth['expiresAt']),'Root start approval expired')
    need(re.fullmatch(r'[a-z0-9-]{1,48}',auth['runId']) is not None,'Run identity invalid')
    folder(BASE);folder(BASE/'private',mode=0o700);folder(BASE/'public')
    if args.action!='upgrade-start':put(BASE/'private/approval.json',api.encoded(auth),mode=0o600)
    if args.action=='install-start':
        put(BASE/'entry.py',read(Path(__file__),256*1024),mode=0o600)
        put(BASE/'start.sh',b'#!/bin/bash\nset -eu\numask 077\nexec /usr/bin/python3 -I -B /var/lib/agentenv-hpab-services-v1/entry.py start\n',mode=0o700)
    fd=os.open(BASE/'private/operation.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if args.action=='upgrade-start':
            old_pin='b072e78f6cd206537a1b06dd1b4efbfaa98fbe38213a3cc944e900764abae927'
            existing=read(BASE/'entry.py',256*1024,owners=(0,))
            journal_path=BASE/'private/journal.json';journal=json.loads(read(journal_path,owners=(0,)))
            if hashlib.sha256(existing).hexdigest()!=pin:
                need(hashlib.sha256(existing).hexdigest()==old_pin and journal['entrySha256']==old_pin,
                     'Only reviewed pre-SDK v1 upgrade is supported')
                need(journal['identity']==identity() and journal['runId']==auth['runId'] and
                    set(journal['steps'])=={'export_code','compile_helpers'} and
                    journal['steps']['export_code']['state']=='done' and journal['steps']['compile_helpers']['state']=='intent'
                    and not journal['units'] and journal['SDK_called'] is False,
                    'Not the confirmed pre-SDK compile failure; preserve all state')
                put(BASE/'private/entry-before-nobuild.py',existing,mode=0o600)
                put(BASE/'private/journal-before-nobuild.json',read(journal_path),mode=0o600)
                put(BASE/'private/approval-before-nobuild.json',read(BASE/'private/approval.json'),mode=0o600)
                journal['sourceUpgrade']={'from':old_pin,'to':pin,'scope':'remove native compilation and udev device grants; service-only'}
                journal['steps']['compile_helpers']['state']='removed_from_start_path'
                journal['entrySha256']=pin;journal['phase']='nobuild_upgrade_confirmed'
                temporary=BASE/'private/journal-nobuild.next'
                put(temporary,wire(journal)+b'\n',mode=0o600);os.replace(temporary,journal_path)
                temporary=BASE/'private/entry-nobuild.next'
                put(temporary,read(Path(__file__),256*1024),mode=0o600);os.replace(temporary,BASE/'entry.py')
            else:need(journal['entrySha256']==pin,'Upgrade state differs')
            temporary=BASE/'private/approval-nobuild.next'
            put(temporary,api.encoded(auth),mode=0o600);os.replace(temporary,BASE/'private/approval.json')
        app=Start(api,auth,control,result,node)
        try:
            if args.action in ('install-start','upgrade-start','start'):app.start()
            elif args.action=='stop':app.stop()
            elif args.action=='restore':
                sys.path.insert(0,str(BASE/'code'));app.restore()
            else:print(json.dumps(app.state,indent=2))
        except BaseException as error:
            app.state['failure']={'phase':app.state['phase'],'errorType':type(error).__name__,
                'reason':str(error) if isinstance(error,RuntimeError) else type(error).__name__}
            app.mark('stopped_preserve_state')
            app.event('failure',app.state['failure'])
            print(json.dumps({'status':'AB_FULL_SERVICES_STOPPED_PRESERVE_STATE',**app.state['failure']}));raise


if __name__=='__main__':
    try:main()
    except Exception as error:
        print(json.dumps({'status':'AB_ROOT_ENTRY_STOPPED_PRESERVE_STATE','errorType':type(error).__name__}),flush=True)
        raise SystemExit(1)
