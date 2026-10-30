"""Transfer one retained observer via the existing private result repository; never execute it."""
import base64,hashlib,importlib.util,json,os,stat,time
from pathlib import Path
SHA='eed36d01de13f83a8abdc13e93c21883a3a48273da83fa1c813e65e4655babcf'
SIZE=24379600
CHUNK=512*1024
RUNNER='b958c459c09db2fe72d508762e8bdab06bd642bfc2f33c6723462ac45353fdcd'
ROOT=Path('/home/jwk/agent')
def need(ok,message):
    if not ok:raise RuntimeError(message)
def main():
    need(os.getuid()==os.geteuid()==1204 and os.getgid()==1205,'Use ordinary jwk')
    os.umask(0o077)
    p=ROOT/'github-relay'/('runner-'+RUNNER[:12]+'.py')
    need(p.resolve()==p and hashlib.sha256(p.read_bytes()).hexdigest()==RUNNER,'Relay source differs')
    s=importlib.util.spec_from_file_location('api',p);api=importlib.util.module_from_spec(s);s.loader.exec_module(api)
    spec=json.loads(Path('task-input.json').read_bytes());current=api.identity()
    need(current==spec['expectedIdentity'],'Node boot differs')
    node=spec['node'];need(node in ('node-a','node-b'),'Unexpected node')
    config=api.load(Path('/home/jwk/.local/state/agentenv-github-relay/config.json'),True)
    need(config['node']==node and config['sessionId']=='relay-20261029-0d032371','Enrollment differs')
    tokens=api.load(Path('/home/jwk/.local/state/agentenv-github-relay/credentials.json'),True)
    client=api.GitHub(tokens['resultToken']);repo='LittleFish-15/AgentENV-relay-results'
    client.private_repo(repo,1438089386)
    original_contents=client.contents
    def contents(*args,**kwargs):
        for attempt in range(3):
            try:return original_contents(*args,**kwargs)
            except api.Network:
                if attempt==2:raise
                time.sleep(2)
    client.contents=contents
    prefix='artifacts/relay-20261029-0d032371/original-observer-'+SHA
    manifest={'sha256':SHA,'bytes':SIZE,'chunkBytes':CHUNK,'chunks':[]}
    if node=='node-a':
        source=ROOT/'relay/reports/node-a-rootfs-access-build-abcks95d/candidate/uvm-ublk-daemon-observe'
        need(source.resolve()==source,'Source redirected');before=source.stat()
        need(stat.S_ISREG(before.st_mode) and before.st_uid==1204 and before.st_size==SIZE,'Source owner/type/size differs')
        # Freeze this bounded artifact in memory; never stream mutable unverified bytes to GitHub.
        raw=source.read_bytes();after=source.stat()
        need(hashlib.sha256(raw).hexdigest()==SHA and
             (before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
             (after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'Source digest/identity changed')
        for i,offset in enumerate(range(0,SIZE,CHUNK)):
            part=raw[offset:offset+CHUNK]
            meta={'index':i,'offset':offset,'bytes':len(part),'sha256':hashlib.sha256(part).hexdigest()}
            packet=dict(meta,data=base64.b64encode(part).decode())
            for attempt in range(3):
                try:client.immutable_result(repo,1438089386,'main',prefix+'/'+str(i)+'.json',api.encoded(packet));break
                except api.Network:
                    if attempt==2:raise
                    time.sleep(3)
            manifest['chunks'].append(meta);print('OBSERVER_CHUNK_UPLOADED='+str(i),flush=True);time.sleep(1)
        for attempt in range(3):
            try:client.immutable_result(repo,1438089386,'main',prefix+'/manifest.json',api.encoded(manifest));break
            except api.Network:
                if attempt==2:raise
                time.sleep(3)
        print('ORIGINAL_OBSERVER_EXPORTED_PRIVATE_NOT_EXECUTED');return
    destination=ROOT/'r/hpd4-b-v1/uvm-ublk-daemon-original-observer'
    need(destination.parent.resolve()==destination.parent and destination.parent.stat().st_uid==1204,'Destination parent differs')
    if destination.exists() or destination.is_symlink():
        need(not destination.is_symlink() and destination.stat().st_uid==1204 and
            hashlib.sha256(destination.read_bytes()).hexdigest()==SHA,'Existing destination differs; preserved')
        print('ORIGINAL_OBSERVER_ALREADY_VERIFIED_NOT_EXECUTED');return
    end=time.monotonic()+750
    while True:
        code,raw,_=client.contents(repo,prefix+'/manifest.json','main')
        if code==200:break
        need(code==404 and time.monotonic()<end,'Observer manifest unavailable; no artifact execution')
        print('WAIT_OBSERVER_MANIFEST',flush=True);time.sleep(10)
    manifest=json.loads(raw)
    need(manifest['sha256']==SHA and manifest['bytes']==SIZE and manifest['chunkBytes']==CHUNK and len(manifest['chunks'])==47,'Manifest differs')
    temporary=destination.with_name(destination.name+'.transfer-partial')
    need(not temporary.exists() and not temporary.is_symlink(),'Prior partial transfer preserved')
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o700)
    total=0;h=hashlib.sha256()
    with os.fdopen(fd,'wb') as f:
        for i,meta in enumerate(manifest['chunks']):
            code,raw,_=client.contents(repo,prefix+'/'+str(i)+'.json','main');need(code==200,'Chunk unavailable')
            row=json.loads(raw);data=base64.b64decode(row.pop('data'),validate=True)
            need(row==meta and meta['index']==i and meta['offset']==total and meta['bytes']==len(data)<=CHUNK
                and hashlib.sha256(data).hexdigest()==meta['sha256'],'Chunk binding differs')
            f.write(data);h.update(data);total+=len(data)
        f.flush();os.fsync(f.fileno())
    need(total==SIZE and h.hexdigest()==SHA,'Full observer digest differs; partial preserved')
    os.link(temporary,destination)
    print(json.dumps({'status':'ORIGINAL_OBSERVER_IMPORTED_VERIFIED_NOT_EXECUTED','bytes':total,'sha256':SHA,
                      'servicesChanged':False,'Guest_created':False,'SDK_called':False}))
if __name__=='__main__':main()
