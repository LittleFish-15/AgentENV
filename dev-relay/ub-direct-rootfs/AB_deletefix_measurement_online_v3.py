"""Online transport for the unchanged pinned measurement pipeline.

Only public code is fetched. Private context stays in human-relayed capsules.
"""
import base64,hashlib,json,os,re,stat,subprocess,textwrap,types,urllib.error,urllib.parse,urllib.request,zlib
from pathlib import Path
ROOT=Path('/home/jwk/agent')
REPOSITORY='LittleFish-15/AgentENV'
PREFIX='dev-relay/ub-direct-rootfs/'
NAME='AB_deletefix_measurement_online_v3.py'
PIPELINE_NAME='AB_deletefix_measurement_pipeline_v1.py'
PIPELINE_COMMIT='12549737c5dc557d5f821068e6d656818a1709a5'
PIPELINE_SHA='87aa3faed883da757e3bd9d8ac22123a1954f0a1407b6ae062bb8a89d4af14ca'
PIPELINE_BYTES=213935

def need(ok,why):
    if not ok:raise RuntimeError(why)

def check_bytes(raw,pin,length):
    need(len(raw)==length and hashlib.sha256(raw).hexdigest()==pin,'Pinned source size/SHA256 mismatch; no execution')
    return raw

class GitHubRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        parsed=urllib.parse.urlparse(newurl)
        need(parsed.scheme=='https' and parsed.netloc in ('raw.githubusercontent.com','api.github.com'),'Unexpected code-download redirect')
        return super().redirect_request(req,fp,code,msg,headers,newurl)

def read_cached(path,pin,length):
    need(path.parent.resolve(strict=True)==path.parent and not path.is_symlink(),'Code cache path redirected')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid in (0,1204) and not before.st_mode&0o022
             and before.st_size==length,'Code cache differs: '+str(path)+' uid='+str(before.st_uid)
             +' mode='+oct(stat.S_IMODE(before.st_mode))+' bytes='+str(before.st_size))
        raw=stream.read(length+1);after=os.fstat(stream.fileno())
        need(all(getattr(before,k)==getattr(after,k) for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')),'Code cache changed during read')
    return check_bytes(raw,pin,length)

def fetch(name,commit,pin,length,opener=None):
    need(re.fullmatch(r'[A-Za-z0-9_]+\.py',name) and re.fullmatch('[0-9a-f]{40}',commit)
         and re.fullmatch('[0-9a-f]{64}',pin) and 0<length<1024**2,'Invalid fixed source request')
    locations=[('api-raw',f'https://api.github.com/repos/{REPOSITORY}/contents/{PREFIX}{name}?ref={commit}'),
               ('raw',f'https://raw.githubusercontent.com/{REPOSITORY}/{commit}/{PREFIX}{name}')]
    errors=[]
    for kind,url in locations:
        try:
            headers={'User-Agent':'aenv-pinned-measurement','Accept-Encoding':'identity','Accept':'application/vnd.github.raw+json' if kind=='api-raw' else 'text/plain'}
            if opener is not None:
                request=urllib.request.Request(url,headers=headers)
                with opener.open(request,timeout=20) as response:body=response.read(length*2+16385)
            else:
                command=['curl','--fail','--location','--silent','--show-error','--connect-timeout','10','--max-time','30','--max-filesize',str(length*2+16384)]
                for key,value in headers.items():command+=['--header',key+': '+value]
                reply=subprocess.run(command+[url],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=35)
                if reply.returncode:raise urllib.error.URLError('curl exit '+str(reply.returncode))
                body=reply.stdout
            if kind=='api':
                need(len(body)<=length*2+16384,'Oversized GitHub response')
                value=json.loads(body);need(value.get('encoding')=='base64','Unexpected GitHub encoding')
                raw=base64.b64decode(value['content'])
            else:raw=body
        except (urllib.error.URLError,TimeoutError,OSError,subprocess.TimeoutExpired,json.JSONDecodeError,KeyError) as error:
            errors.append({'endpoint':kind,'errorType':type(error).__name__,'httpStatus':getattr(error,'code',None)})
            continue
        return check_bytes(raw,pin,length)
    raise RuntimeError('Pinned GitHub source unavailable: '+json.dumps(errors)+'; no pipeline phase started')

def ensure_code(name,commit,pin,length):
    need(ROOT.resolve(strict=True)==ROOT,'Agent directory redirected')
    path=ROOT/name
    if path.exists() or path.is_symlink():return path,read_cached(path,pin,length)
    raw=fetch(name,commit,pin,length)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fchmod(stream.fileno(),0o600);os.fsync(stream.fileno())
    return path,raw

def online_command(phase,node,context,release,adapter_sha,adapter_bytes):
    need(re.fullmatch('[0-9a-f]{40}',release) and re.fullmatch('[0-9a-f]{64}',adapter_sha)
         and type(adapter_bytes) is int and 0<adapter_bytes<=65536,'Online release pin missing')
    data=json.dumps(context,sort_keys=True,separators=(',',':')).encode()
    need(len(data)<=16*1024**2,'Private context exceeds relay budget')
    capsule='\n'.join(textwrap.wrap(base64.b64encode(zlib.compress(data,9)).decode(),100))
    host={'a':'server1','b':'agent1'}[node]
    # Bootstrap downloads the small public adapter; the adapter reuses/fetches
    # the unchanged public pipeline. The capsule is never part of an HTTP call.
    return f'''python3 -I -B - <<'ONLINE_MEASUREMENT_RELAY'
import base64,hashlib,json,os,platform,stat,subprocess,sys,zlib
from pathlib import Path
assert os.getuid()==os.geteuid()==0 and platform.node()=={host!r},'Root on {host} required'
data=zlib.decompress(base64.b64decode("""{capsule}"""))
assert hashlib.sha256(data).hexdigest()=={hashlib.sha256(data).hexdigest()!r}
root=Path('/home/jwk/agent');assert root.resolve(strict=True)==root
p=root/{NAME!r};pin={adapter_sha!r};size={adapter_bytes};release={release!r}
if p.exists() or p.is_symlink():
 assert not p.is_symlink() and p.resolve(strict=True)==p
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 with os.fdopen(fd,'rb') as stream:
  meta=os.fstat(stream.fileno());assert stat.S_ISREG(meta.st_mode) and meta.st_uid in (0,1204) and meta.st_mode&0o022==0 and meta.st_size==size, f'Code cache metadata differs: {{p}} uid={{meta.st_uid}} mode={{oct(stat.S_IMODE(meta.st_mode))}} bytes={{meta.st_size}}'
  raw=stream.read(size+1)
else:
 raw=None
 urls=[('api-raw',f'https://api.github.com/repos/{REPOSITORY}/contents/{PREFIX}{NAME}?ref={{release}}'),('raw',f'https://raw.githubusercontent.com/{REPOSITORY}/{{release}}/{PREFIX}{NAME}')]
 for kind,url in urls:
  try:
   accept='application/vnd.github.raw+json' if kind=='api-raw' else 'text/plain'
   reply=subprocess.run(['curl','--fail','--location','--silent','--show-error','--connect-timeout','10','--max-time','30','--max-filesize',str(size*2+16384),'--header','Accept: '+accept,'--header','Accept-Encoding: identity','--header','User-Agent: aenv-pinned-online-bootstrap',url],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=35)
   if reply.returncode:continue
   raw=reply.stdout
   break
  except (OSError,subprocess.TimeoutExpired):pass
 assert raw is not None,'GitHub download failed; no measurement phase started'
 assert len(raw)==size and hashlib.sha256(raw).hexdigest()==pin,'Downloaded adapter checksum mismatch'
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fchmod(stream.fileno(),0o600);os.fsync(stream.fileno())
assert len(raw)==size and hashlib.sha256(raw).hexdigest()==pin
scope={{'__name__':'verified_online_transport','__file__':str(p)}}
exec(compile(raw,str(p),'exec'),scope)
raise SystemExit(scope['run_online']({phase!r},json.loads(data),release,pin,size))
ONLINE_MEASUREMENT_RELAY'''

def run_online(phase,context,release,adapter_sha,adapter_bytes):
    need(os.getuid()==os.geteuid()==0,'Root execution required')
    node={'server1':'a','agent1':'b'}[os.uname().nodename]
    need(phase.endswith('-'+node),'Wrong node for phase')
    read_cached(Path(__file__),adapter_sha,adapter_bytes)
    path,raw=ensure_code(PIPELINE_NAME,PIPELINE_COMMIT,PIPELINE_SHA,PIPELINE_BYTES)
    pipeline=types.ModuleType('unchanged_pinned_pipeline');pipeline.__file__=str(path)
    exec(compile(raw,str(path),'exec'),pipeline.__dict__)
    pipeline.relay=lambda next_phase,next_node,next_context,source=None:online_command(next_phase,next_node,next_context,release,adapter_sha,adapter_bytes)
    print('ONLINE_PINNED_MEASUREMENT_PIPELINE_READY',flush=True)
    return pipeline.run(phase,context)
