"""Independent jwk runtime and unprivileged namespace relays/benchmark runner."""
import asyncio,ctypes,json,os,pathlib,pwd,shutil,socket,struct,subprocess,sys,time,ssl
from urllib.parse import urlsplit
BASE=pathlib.Path('/home/jwk/aenv-y-clean-20261111');IPC=BASE/'r'
CAPS=(1<<21)|(1<<12)
ALLOWED=('github.com','githubusercontent.com','ghcr.io','docker.io','docker.com','amazonaws.com','cloudfront.net',
 'myhuaweicloud.com','huaweicloud.com','quay.io','gcr.io','pkg.dev','googleapis.com')
def require(ok,message):
    if not ok:raise RuntimeError(message)
def caps():
    return {a:int(b.strip(),16) for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line
      for a,b in [line.split(':',1)] if a in ('CapEff','CapPrm','CapInh','CapAmb')}
def drop_caps():
    class Header(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
    class Data(ctypes.Structure):_fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
    libc=ctypes.CDLL(None,use_errno=True)
    require(libc.prctl(47,4,0,0,0)==0,'Cannot clear ambient capabilities')
    require(libc.capset(ctypes.byref(Header(0x20080522,0)),ctypes.byref((Data*2)()))==0,'Cannot clear relay capabilities')
    require(not any(caps().values()),'Relay capability drop failed')
def identity():
    require(os.geteuid()!=0 and pwd.getpwuid(os.geteuid()).pw_name=='jwk','Must run as jwk')
    require(BASE.resolve()==BASE and BASE.stat().st_uid==os.geteuid(),'Unexpected private deployment path');os.umask(0o077)
def peer_is_jwk(writer):
    value=writer.get_extra_info('socket').getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)
    return struct.unpack('3i',value)[1]==os.geteuid()
def prepare_socket(path):
    if not path.exists() and not path.is_symlink():return
    require(not path.is_symlink() and path.is_socket() and path.stat().st_uid==os.geteuid(),'Unexpected IPC object preserved')
    signature=(path.stat().st_dev,path.stat().st_ino)
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as probe:
        probe.settimeout(1)
        try:probe.connect(str(path))
        except ConnectionRefusedError:
            require((path.stat().st_dev,path.stat().st_ino)==signature,'IPC object changed during check');path.unlink()
        else:raise RuntimeError('Existing live IPC endpoint preserved')
async def relay(reader,writer,other_reader,other_writer):
    async def pump(source,dest):
        while data:=await source.read(65536):dest.write(data);await dest.drain()
        if dest.can_write_eof():dest.write_eof()
    try:await asyncio.wait_for(asyncio.gather(pump(reader,other_writer),pump(other_reader,writer)),7200)
    except (OSError,ConnectionError,asyncio.TimeoutError):pass
    finally:writer.close();other_writer.close()
async def endpoint(mode):
    identity();require(not any(caps().values()),'Relays must be unprivileged')
    proxy=json.loads((BASE/'config/egress-proxy.json').read_text())
    async def accept(reader,writer):
        try:
            if mode in ('api-inside','egress-host'):require(peer_is_jwk(writer),'Unexpected UNIX peer')
            if mode=='api-host':other_reader,other_writer=await asyncio.open_unix_connection(str(IPC/'api.sock'))
            elif mode=='api-inside':other_reader,other_writer=await asyncio.open_connection('127.0.0.1',18080)
            elif mode=='egress-inside':other_reader,other_writer=await asyncio.open_unix_connection(str(IPC/'egress.sock'))
            else:
                header=await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'),30);require(len(header)<65536,'Oversized proxy request')
                method,target,version=header.split(b'\r\n',1)[0].decode('ascii').split(' ',2)
                parsed=urlsplit('//'+target if method=='CONNECT' else target);host=parsed.hostname or '';port=parsed.port or (443 if method=='CONNECT' else 80)
                require(any(host==s or host.endswith('.'+s) for s in ALLOWED) and port in (80,443),'Destination outside registry allowlist')
                upstream=proxy.get('https' if method=='CONNECT' else 'http')
                if upstream:
                    remote=urlsplit(upstream);require(remote.scheme in ('http','https') and remote.hostname,'Unsupported upstream proxy')
                    require(remote.username is None and remote.password is None,'Authenticated upstream proxy requires a separate jwk credential')
                    context=ssl.create_default_context(cafile=proxy['ca']) if remote.scheme=='https' else None
                    other_reader,other_writer=await asyncio.wait_for(asyncio.open_connection(remote.hostname,remote.port or (443 if context else 80),ssl=context),30)
                    other_writer.write(header);await other_writer.drain()
                    if method=='CONNECT':
                        response=await asyncio.wait_for(other_reader.readuntil(b'\r\n\r\n'),30)
                        require(response.split(b'\r\n',1)[0].split()[1]==b'200','Upstream proxy rejected tunnel')
                        writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n');await writer.drain()
                else:
                    other_reader,other_writer=await asyncio.wait_for(asyncio.open_connection(host,port),30)
                    if method=='CONNECT':writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n');await writer.drain()
                    else:
                        require(parsed.scheme=='http','Expected HTTP URL')
                        path=(parsed.path or '/')+('?' + parsed.query if parsed.query else '')
                        other_writer.write((method+' '+path+' '+version).encode()+b'\r\n'+header.split(b'\r\n',1)[1]);await other_writer.drain()
            await relay(reader,writer,other_reader,other_writer)
        except Exception as error:
            print(json.dumps({'mode':mode,'error':type(error).__name__,'detail':str(error)[:200]}),flush=True);writer.close()
    if mode in ('api-inside','egress-host'):
        path=IPC/('api.sock' if mode=='api-inside' else 'egress.sock');prepare_socket(path)
        server=await asyncio.start_unix_server(accept,str(path));path.chmod(0o600)
    else:server=await asyncio.start_server(accept,'127.0.0.1',18080 if mode=='api-host' else 18089,reuse_address=False)
    (IPC/(mode+'.json')).write_text(json.dumps({'pid':os.getpid(),'uid':os.geteuid(),'netns':os.stat('/proc/self/ns/net').st_ino,'caps':caps()})+'\n')
    async with server:await server.serve_forever()
async def benchmark():
    identity();require(not any(caps().values()),'Benchmark runner must have no capabilities')
    lock=asyncio.Lock();path=IPC/'benchmark.sock';prepare_socket(path)
    async def accept(reader,writer):
        disconnected=False
        async def send(data):
            nonlocal disconnected
            if disconnected:return
            try:writer.write(data);await writer.drain()
            except (OSError,ConnectionError):disconnected=True
        try:
            require(peer_is_jwk(writer),'Unexpected benchmark peer')
            raw=await asyncio.wait_for(reader.readline(),10);require(len(raw)<4096,'Oversized benchmark request')
            request=json.loads(raw);rounds=request.get('rounds',5)
            require(type(rounds) is int and 1<=rounds<=10,'Rounds must be1..10');require(not lock.locked(),'A benchmark is already running')
            image_map=BASE/'config/bench_image_map.json';require(image_map.is_file(),'Native Wikidata717 template is not provisioned yet')
            async with lock:
                result=BASE/'results'/('lifecycle-'+time.strftime('%Y%m%d-%H%M%S')+'-'+os.urandom(3).hex());result.mkdir(parents=True,mode=0o700)
                environment=dict(os.environ)
                for name in ('http_proxy','https_proxy','all_proxy','ftp_proxy','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','FTP_PROXY','PYTHONPATH','PYTHONHOME'):environment.pop(name,None)
                environment.update(E2B_API_KEY=(BASE/'config/api-key').read_text().strip(),E2B_ACCESS_TOKEN='dummy',
                  NO_PROXY='localhost,127.0.0.1',no_proxy='localhost,127.0.0.1',PYTHONNOUSERSITE='1',PYTHONUNBUFFERED='1')
                proof={'uid':os.geteuid(),'caps':caps(),'netns':os.stat('/proc/self/ns/net').st_ino,'api':'direct Rust 127.0.0.1:18080','rounds':rounds}
                (result/'transport.json').write_text(json.dumps(proof)+'\n')
                await send(('RESULT_DIR='+str(result)+'\n').encode())
                for label,count in [('prewarm100',1),('formal',rounds)]:
                    args=[str(BASE/'sdk/g4-e2b246/bin/python'),'-B',str(BASE/'g4-benchmark_sandbox_lifecycle.py'),
                      '--api-url','http://127.0.0.1:18080','--total','100','--batch-size','100','--rounds',str(count),
                      '--image-map',str(image_map),'--output-dir',str(result/label)]
                    process=await asyncio.create_subprocess_exec(*args,env=environment,stdin=asyncio.subprocess.DEVNULL,
                      stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.STDOUT)
                    with (result/(label+'.log')).open('xb') as log:
                        while data:=await process.stdout.readline():log.write(data);log.flush();await send(data)
                    code=await process.wait();require(code==0,label+' benchmark failed, exit='+str(code))
                await send(b'BENCHMARK_EXIT=0\n')
        except Exception as error:
            await send(('BENCHMARK_ERROR='+str(error)+'\n').encode())
        finally:writer.close()
    server=await asyncio.start_unix_server(accept,str(path));path.chmod(0o600)
    async with server:await server.serve_forever()
def start_child(mode,env=None,drop=False):
    log=(BASE/'logs'/(mode+'.log')).open('ab',buffering=0)
    child=subprocess.Popen(['/usr/bin/python3','-I','-B',__file__,mode],env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=log,preexec_fn=drop_caps if drop else None)
    time.sleep(.25);require(child.poll() is None,'Runtime helper failed: '+mode);return child
def inside():
    identity();context=json.loads((BASE/'config/host-context008.json').read_text())
    require(pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()==context['boot_id'],'Boot differs')
    require(os.stat('/proc/self/ns/net').st_ino!=context['netns'] and os.stat('/proc/self/ns/mnt').st_ino!=context['mntns'],'Refuse host namespace execution')
    require(all(v==CAPS for v in caps().values()),'Unexpected runtime capability set')
    for device in ('/dev/kvm','/dev/ublk-control','/dev/net/tun'):
        fd=os.open(device,os.O_RDWR|os.O_CLOEXEC);os.close(fd)
    subprocess.run([shutil.which('ip'),'link','set','dev','lo','up'],check=True)
    pathlib.Path('/proc/sys/net/ipv4/ip_forward').write_text('1\n')
    ca=json.loads((BASE/'config/egress-proxy.json').read_text())['ca']
    environment={'HOME':pwd.getpwuid(os.geteuid()).pw_dir,'USER':'jwk','LOGNAME':'jwk','LANG':'C.UTF-8',
      'PATH':str(BASE/'bin')+':/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin','TMPDIR':str(BASE/'tmp'),
      'XDG_CACHE_HOME':str(BASE/'cache'),'DOCKER_CONFIG':str(BASE/'config/docker'),'SSL_CERT_FILE':ca,'CURL_CA_BUNDLE':ca,
      'AENV_HOME_PATH':str(BASE/'state'),'AENV_RUNTIME_PATH':str(IPC),'AENV_DEPS_PATH':str(BASE/'runtime-assets'),
      'XTABLES_LOCKFILE':str(IPC/'xtables014.lock'),'API_ADDR':'127.0.0.1:18080','AENV_LOG_FORMAT':'compact','RUST_LOG':'agentenv=warn',
      'HTTP_PROXY':'http://127.0.0.1:18089','HTTPS_PROXY':'http://127.0.0.1:18089',
      'http_proxy':'http://127.0.0.1:18089','https_proxy':'http://127.0.0.1:18089',
      'NO_PROXY':'localhost,127.0.0.1,10.11.0.0/16,10.12.0.0/16,169.254.0.0/16',
      'no_proxy':'localhost,127.0.0.1,10.11.0.0/16,10.12.0.0/16,169.254.0.0/16'}
    command_rows=json.loads((BASE/'config/runtime-command-proof014.json').read_text())
    checks=[]
    for row in command_rows:
        found=shutil.which(row['command'],path=environment['PATH'])
        require(found is not None,'Required command missing inside runtime: '+row['command'])
        require(str(pathlib.Path(found).resolve(strict=True))==row['resolved'],'Runtime command target differs: '+row['command'])
        checks.append({'command':row['command'],'resolved':row['resolved']})
    versions={}
    for name in ('iptables-restore','iptables-save'):
        probe=subprocess.run([shutil.which(name,path=environment['PATH']),'--version'],env=environment,
            capture_output=True,text=True,timeout=15)
        require(probe.returncode==0,'Native firewall executable failed: '+name+' '+probe.stderr[-1000:])
        versions[name]=probe.stdout.strip()
    (IPC/'runtime-preflight014.json').write_text(json.dumps({'uid':os.geteuid(),'netns':os.stat('/proc/self/ns/net').st_ino,
        'commands':checks,'firewallVersions':versions,'xtablesLockfile':environment['XTABLES_LOCKFILE']})+'\n')
    for mode in ('api-inside','egress-inside','benchmark'):start_child(mode,environment,drop=True)
    environment['AENV_API_KEY']=(BASE/'config/api-key').read_text().strip()
    (IPC/'runtime-attestation008.json').write_text(json.dumps({'pid':os.getpid(),'uid':os.geteuid(),'netns':os.stat('/proc/self/ns/net').st_ino,
      'mntns':os.stat('/proc/self/ns/mnt').st_ino,'caps':caps(),'boot_id':context['boot_id']})+'\n')
    fd=os.open(BASE/'logs/server.log',os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600);os.dup2(fd,1);os.dup2(fd,2);os.close(fd)
    os.chdir(BASE);binary=BASE/'bin/server';os.execve(binary,[str(binary),'--config',str(BASE/'config/runtime005.toml')],environment)
if __name__=='__main__':
    mode=sys.argv[1]
    if mode=='inside':inside()
    elif mode=='host':
        identity();children=[start_child(name) for name in ('api-host',)]
        while all(p.poll() is None for p in children):time.sleep(1)
        raise SystemExit('Host relay exited')
    elif mode=='benchmark':asyncio.run(benchmark())
    elif mode in ('api-host','api-inside','egress-host','egress-inside'):asyncio.run(endpoint(mode))
    else:raise SystemExit('Unknown mode')
