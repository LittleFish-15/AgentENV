#!/usr/bin/env bash
/usr/bin/python3 -I -B - <<'GET_PINNED_SINGLE_V1' && /usr/bin/python3 -I -B /home/jwk/agent/lazy-single-v1/lazy_four_rollout.py run-a --run
import base64,hashlib,json,os,socket,stat,time,urllib.request
from pathlib import Path
assert os.getuid()==os.geteuid()==1204 and socket.gethostname()=='server1'
os.umask(0o077)
root=Path('/home/jwk/agent');assert root.resolve(strict=True)==root and root.stat().st_uid==1204
folder=root/'lazy-single-v1';folder.mkdir(mode=0o700,exist_ok=True)
assert folder.resolve(strict=True)==folder and folder.stat().st_uid==1204
path=folder/'lazy_four_rollout.py'
pin='f1b302c7f75242268b5b3742365e6a2eaeb18927905593386eb0d52436c8fd7f'
blob='670a742959eb8f9e37623d5fec92f4994b6eb64f'
assert not path.is_symlink()
if path.exists():
    meta=path.stat();assert stat.S_ISREG(meta.st_mode) and meta.st_uid==1204 and meta.st_size<=8*1024**2
    assert hashlib.sha256(path.read_bytes()).hexdigest()==pin,'Different existing entry preserved'
else:
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs):raise RuntimeError('Unexpected public-source redirect')
    opener=urllib.request.build_opener(NoRedirect())
    url='https://api.github.com/repos/LittleFish-15/AgentENV/git/blobs/'+blob
    for attempt in range(3):
        try:
            print('DOWNLOAD_PINNED_GIT_BLOB attempt='+str(attempt+1),flush=True)
            request=urllib.request.Request(url,headers={'Accept':'application/vnd.github+json','User-Agent':'agentenv-reviewed-cow-v3'})
            with opener.open(request,timeout=90) as response:payload=response.read(12*1024**2+1)
            assert len(payload)<=12*1024**2
            item=json.loads(payload);assert item['sha']==blob and item['encoding']=='base64'
            data=base64.b64decode(''.join(item['content'].split()),validate=True)
            assert len(data)==item['size']==5048236 and len(data)<=8*1024**2
            assert hashlib.sha256(data).hexdigest()==pin
            assert hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==blob
            break
        except Exception:
            if attempt==2:raise
            time.sleep(2*(attempt+1))
    with path.open('xb') as output:output.write(data);output.flush();os.fsync(output.fileno())
print('PINNED_SINGLE_V1_ENTRY_VERIFIED',flush=True)
GET_PINNED_SINGLE_V1
