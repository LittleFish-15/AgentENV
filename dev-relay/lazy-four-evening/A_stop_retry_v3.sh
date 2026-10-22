#!/usr/bin/env bash
/usr/bin/python3 -I -B - <<'GET_PINNED_OBSERVED_V3' && /usr/bin/python3 -I -B /home/jwk/agent/lazy-four-v3/lazy_four_rollout.py stop-a --run
import base64,hashlib,json,os,socket,stat,time,urllib.request
from pathlib import Path
assert os.getuid()==os.geteuid()==1204 and socket.gethostname()=='server1'
os.umask(0o077)
root=Path('/home/jwk/agent');assert root.resolve(strict=True)==root and root.stat().st_uid==1204
folder=root/'lazy-four-v3';folder.mkdir(mode=0o700,exist_ok=True)
assert folder.resolve(strict=True)==folder and folder.stat().st_uid==1204
path=folder/'lazy_four_rollout.py'
pin='1d8623e7173f09633d39e6eba94241f0afdef98992b427618ae1980b29caf5c5'
blob='c36423102e7d88a9ad9d339bbe2aac551b1b2b2d'
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
            assert len(data)==item['size']==4980872 and len(data)<=8*1024**2
            assert hashlib.sha256(data).hexdigest()==pin
            assert hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==blob
            break
        except Exception:
            if attempt==2:raise
            time.sleep(2*(attempt+1))
    with path.open('xb') as output:output.write(data);output.flush();os.fsync(output.fileno())
print('PINNED_OBSERVED_V3_ENTRY_VERIFIED',flush=True)
GET_PINNED_OBSERVED_V3
