"""Download one fixed public native candidate entry; preserve any differing local file."""
import argparse,base64,hashlib,json,os,socket,stat,sys,time,urllib.error,urllib.request,uuid
from pathlib import Path

RELEASE={'commit': '095d02c0e821419b0177d6598bfb89c1cd10fe40', 'sha256': '6a620b41d86089a878dd46b07eacde5fe531289ed33b0df275641e4d75be5713', 'bytes': 3681027, 'blob': '95415df71deccca16c468bd5ad48b502e3457d49'}
ROOT=Path('/home/jwk/agent')

class OfficialOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise RuntimeError('Unexpected redirect from the pinned GitHub API')

def need(ok,message):
    if not ok:raise RuntimeError(message)

def validate(data):
    need(len(data)==RELEASE['bytes'] and hashlib.sha256(data).hexdigest()==RELEASE['sha256'],'Native entry checksum or length differs')
    need(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==RELEASE['blob'],'Native Git blob differs')

def download():
    client=urllib.request.build_opener(OfficialOnly())
    request=urllib.request.Request('https://api.github.com/repos/LittleFish-15/AgentENV/git/blobs/'+RELEASE['blob'],
        headers={'Accept':'application/vnd.github+json','User-Agent':'agentenv-native-round-bootstrap'})
    for attempt in range(3):
        try:
            with client.open(request,timeout=180) as response:
                need(response.status==200,'GitHub API response failed');raw=response.read(12*1024**2+1)
            need(len(raw)<=12*1024**2,'GitHub blob response exceeds bound')
            value=json.loads(raw)
            need(value.get('sha')==RELEASE['blob'] and value.get('encoding')=='base64' and value.get('size')==RELEASE['bytes'],'GitHub blob metadata differs')
            data=base64.b64decode(''.join(value['content'].split()),validate=True);validate(data);return data
        except (urllib.error.URLError,TimeoutError):
            if attempt==2:raise
            print('GITHUB_API_RETRY='+str(attempt+1),flush=True);time.sleep(2)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--scenario',choices=('single-a','dual-ab'),required=True)
    p.add_argument('--replica-mode',choices=('restore-pair','restore-fork','restore-fork-parallel'),default='restore-pair');p.add_argument('--run',action='store_true');a=p.parse_args()
    need(sys.platform=='linux' and os.getuid()==os.geteuid()==1204 and socket.gethostname()=='server1','Use the ordinary A experiment user')
    need(ROOT.resolve(strict=True)==ROOT and ROOT.stat().st_uid==1204,'Experiment directory differs');os.umask(0o077)
    path=ROOT/'native_archive_round.py'
    need(not path.is_symlink(),'Existing redirected entry preserved')
    if path.exists():
        meta=path.stat();need(stat.S_ISREG(meta.st_mode) and meta.st_uid==1204 and meta.st_nlink==1 and meta.st_size==RELEASE['bytes'],'Existing entry differs; preserved')
        validate(path.read_bytes())
    else:
        data=download();temporary=ROOT/('native_archive_round.download-'+uuid.uuid4().hex)
        with temporary.open('xb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
        # Exclusive destination publication, with interrupted download preserved.
        os.link(temporary,path);temporary.unlink()
    print('PINNED_NATIVE_ROUND_ENTRY_READY commit='+RELEASE['commit'],flush=True)
    if not a.run:return 0
    os.execv('/usr/bin/python3',['/usr/bin/python3','-I','-B',str(path),'run-a','--scenario',a.scenario,'--replica-mode',a.replica_mode,'--run'])

if __name__=='__main__':raise SystemExit(main())
