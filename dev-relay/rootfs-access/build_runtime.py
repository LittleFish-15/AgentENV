"""Ordinary-user build of an isolated original-source observation daemon.

BASE_ARCHIVE/PATCH_FILES are supplied by the deterministic public-source bundle.
No service, kernel, SDK, Guest, or installed binary is changed by this builder.
"""
import argparse, base64, hashlib, io, json, os, re, shutil, signal, socket, stat, struct, subprocess, sys, tarfile, tempfile, time, zlib
from pathlib import Path
ROOT=Path('/home/jwk/agent')
CACHE=ROOT/'builds/agentenv-ub-build-v2'
RUST=ROOT/'toolchains/agentenv-rust-1.99.0/rustup/toolchains/1.99.0-aarch64-unknown-linux-gnu/bin'
STATE=ROOT/'relay/cow4-rootfs-access-build-v2.json'
def need(ok,why):
    if not ok:raise RuntimeError(why)
def save(path,value):
    temporary=path.with_name(path.name+'.tmp')
    with temporary.open('x',encoding='utf-8') as f:json.dump(value,f,indent=2);f.flush();os.fsync(f.fileno())
    os.replace(temporary,path)
def unpack(source):
    need(hashlib.sha256(json.dumps(PATCH_FILES,sort_keys=True,separators=(',',':')).encode()).hexdigest()==PATCH_SHA,'Patch manifest checksum differs')
    raw=zlib.decompress(base64.b64decode(BASE_ARCHIVE['base64'],validate=True))
    need(hashlib.sha256(raw).hexdigest()==BASE_ARCHIVE['sha256'],'Base archive checksum differs')
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
        members=archive.getmembers();need(len(members)<5000 and sum(m.size for m in members)<100*1024**2,'Source archive exceeds budget')
        for m in members:
            p=Path(m.name);need(not p.is_absolute() and '..' not in p.parts and '\\' not in m.name,'Invalid source member')
            if m.issym():
                need(m.name=='AGENTS.md' and m.linkname=='CLAUDE.md','Unexpected source symlink')
                continue # instruction-file alias is not a compiler input
            target=source/p
            if m.isdir():target.mkdir(parents=True,exist_ok=True);continue
            need(m.isfile(),'Unexpected source member kind');target.parent.mkdir(parents=True,exist_ok=True)
            with target.open('xb') as f:f.write(archive.extractfile(m).read())
            os.chmod(target,0o700 if m.mode&0o111 else 0o600)
    for name,item in PATCH_FILES.items():
        p=source/name;before=item['before_sha256']
        need((p.exists() and hashlib.sha256(p.read_bytes()).hexdigest()==before) if before else not p.exists(),'Patch preimage differs: '+name)
        raw=base64.b64decode(item['base64'],validate=True);need(hashlib.sha256(raw).hexdigest()==item['after_sha256'],'Patch bytes differ')
        p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
    need(hashlib.sha256((source/'Cargo.lock').read_bytes()).hexdigest()==LOCK_SHA,'Original Cargo.lock changed')

def verify_calibration(directory):
    code=base64.b64decode(ACCOUNTING_BASE64,validate=True)
    need(hashlib.sha256(code).hexdigest()==ACCOUNTING_SHA,'Accounting source differs')
    namespace={'__name__':'calibration_accounting'};exec(compile(code,'embedded-page-accounting','exec'),namespace)
    value=json.loads((directory/'calibration-input.json').read_bytes())
    key=(value['dev'],value['inode']);files={key:{'path':value['fixture'],'file_bytes':value['file_bytes']}}
    bindings={value['source'+str(i)]:{'sandbox_id':str(i),'template_id':'calibration','lower_keys':{key},'upper_keys':set()} for i in (1,2)}
    windows={str(i):(value['start_ns'],value['end_ns']) for i in (1,2)}
    status=json.loads((directory/'trace.status.json').read_bytes())
    with (directory/'trace.jsonl').open() as stream:
        sets,audit=namespace['read_sets'](stream,status,bindings,windows,files,PATCH_SHA)
    need(audit['records_checked']==3,'Warm repeat read missing or extra calibration events')
    observed=sets['1']|sets['2'];resident,meta=namespace['resident_accessed_pages'](files,observed)
    measured=namespace['pair_statistics'](sets['1'],sets['2'],resident)
    need(measured['sandbox1_accessed_lower_bytes']==measured['sandbox2_accessed_lower_bytes']==8192,'Calibration source attribution differs')
    need(measured['shared_accessed_host_pagecache_bytes']==4096 and measured['accessed_resident_union_bytes']==12288,'Calibration overlap differs')
    all_pages={(key[0],key[1],i) for i in range(value['file_bytes']//4096)}
    whole_resident,_=namespace['resident_accessed_pages'](files,all_pages)
    need(whole_resident==all_pages,'Warm fixture no longer fully resident; calibration not established')
    return {'status':'WARM_BUFFERED_READ_ATTRIBUTION_AND_RESIDENT_INTERSECTION_VERIFIED',
        'whole_fixture_written_bytes':value['file_bytes'],'whole_fixture_resident_bytes':len(whole_resident)*4096,
        'whole_fixture_residency_independently_measured':True,
        'known_accessed_union_bytes':12288,'known_common_page_bytes':4096,'warm_repeated_read_observed':True,
        'io_uring_actual_execution':True,'Guest_or_ublk_execution':False,'audit':audit,'measurement':measured,'sampler':meta}
def main():
    parser=argparse.ArgumentParser();parser.add_argument('mode',choices=('build','status'));a=parser.parse_args()
    need(sys.platform=='linux' and os.getuid()==os.geteuid()==1204 and socket.gethostname()=='server1','A/server1 ordinary jwk only')
    need(os.uname().machine=='aarch64','Expected ARM64 build host');os.umask(0o077)
    caps=dict(x.split(':',1) for x in Path('/proc/self/status').read_text().splitlines() if ':' in x)
    need(all(int(caps[k].strip(),16)==0 for k in ('CapEff','CapPrm','CapAmb')),'Capability-free builder required')
    if a.mode=='status':print('BEGIN_RETURN_REPORT');print(STATE.read_text());print('END_RETURN_REPORT');return 0
    import fcntl
    lock=os.open(ROOT/'relay/cow4-rootfs-access-build.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    need(not STATE.exists(),'Build receipt already exists; use status rather than repeat')
    for p in (ROOT,CACHE,CACHE/'cargo',CACHE/'target',RUST,RUST/'cargo',RUST/'rustc'):
        need(p.exists() and p.resolve(strict=True)==p,'Expected existing build input absent/redirected: '+str(p))
    need(shutil.disk_usage(ROOT).free>=32*1024**3,'Need 32GiB available build space')
    version=subprocess.check_output([str(RUST/'rustc'),'-V'],text=True,timeout=15).strip()
    need(version.startswith('rustc 1.99.0 '),'Existing compiler version differs')
    work=Path(tempfile.mkdtemp(prefix='node-a-rootfs-access-build-',dir=ROOT/'relay/reports'))
    source=work/'source';source.mkdir();report={'status':'BUILDING_OBSERVATION_DAEMON','base_commit':BASE_COMMIT,'work_directory':str(work),
        'rustc':version,'service_changed':False,'SDK_called':False,'Guest_created':False,'kernel_changed':False,
        'dependency_mode':'frozen_offline_existing_cache','phases':{},'patch_sha256':PATCH_SHA}
    save(STATE,report)
    try:
        print('PHASE=prepare_original_source_with_read_observer',flush=True);unpack(source)
        env=dict(os.environ)
        for k in list(env):
            if k.startswith('GIT_') or k in ('RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','CARGO_BUILD_TARGET','LD_PRELOAD','LD_AUDIT'):env.pop(k,None)
        env.update(CARGO_HOME=str(CACHE/'cargo'),CARGO_TARGET_DIR=str(CACHE/'target'),RUSTC=str(RUST/'rustc'),
            RUSTDOC=str(RUST/'rustdoc'),PATH=str(RUST)+os.pathsep+env.get('PATH',''),CARGO_NET_OFFLINE='true',
            CARGO_BUILD_JOBS='4',CMAKE_BUILD_PARALLEL_LEVEL='4',CARGO_INCREMENTAL='0',CARGO_PROFILE_DEV_DEBUG='0',CARGO_PROFILE_TEST_DEBUG='0',
            GIT_TERMINAL_PROMPT='0',GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null')
        env['AENV_OBSERVER_BUILD_PATCH_SHA']=PATCH_SHA
        for variable,name in [('TMPDIR','tmp'),('XDG_CACHE_HOME','cache'),('XDG_CONFIG_HOME','config'),('XDG_STATE_HOME','state')]:
            p=work/name;p.mkdir();env[variable]=str(p)
        if Path('/usr/lib64/libclang.so').is_file():env['LIBCLANG_PATH']='/usr/lib64'
        if shutil.which('protoc'):env['PROTOC']=shutil.which('protoc')
        config=work/'offline.toml';config.write_text('[net]\noffline = true\n')
        cargo=[str(RUST/'cargo'),'--config',str(config)]
        def run(name,args):
            print('PHASE='+name,flush=True);began=time.monotonic();last=began;log=work/(name+'.log')
            with log.open('xb') as output:
                p=subprocess.Popen(cargo+args,cwd=source,env=env,stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
                try:
                    while p.poll() is None:
                        time.sleep(2);need(time.monotonic()-began<=1800,'Own build phase exceeded 30-minute bound')
                        if time.monotonic()-last>=30:
                            print('BUILD_HEARTBEAT phase='+name+' elapsed_seconds='+str(round(time.monotonic()-began)),flush=True);last=time.monotonic()
                except BaseException:
                    if p.poll() is None:
                        os.killpg(p.pid,signal.SIGTERM)
                        try:p.wait(timeout=15)
                        except subprocess.TimeoutExpired:report['own_build_process_group_exit_unconfirmed']=p.pid
                    raise
                report['phases'][name]=p.returncode;save(STATE,report)
                if p.returncode:
                    with log.open('rb') as f:f.seek(max(0,log.stat().st_size-16000));tail=f.read().decode(errors='replace')
                    report['failure_log_tail']=re.sub(r'e2b_[A-Za-z0-9._~-]+','[REDACTED]',tail)
                need(p.returncode==0,name+' failed; read '+str(log))
        run('test_observer',['test','--frozen','-p','overlaybd','--features','io-uring,rootfs-read-trace','--lib','rootfs_access_trace::','--','--test-threads=1'])
        run('build_calibration',['build','--frozen','--release','-p','overlaybd','--features','io-uring,rootfs-read-trace','--example','rootfs_access_calibration'])
        calibration=work/'calibration';calibration.mkdir(mode=0o700)
        probe=calibration/'probe'
        with (CACHE/'target/release/examples/rootfs_access_calibration').open('rb') as src,probe.open('xb') as dst:shutil.copyfileobj(src,dst)
        os.chmod(probe,0o700)
        need(PATCH_SHA.encode() in probe.read_bytes(),'Calibration executable build digest differs')
        print('PHASE=calibrate_warm_file_access_intersection',flush=True)
        result=subprocess.run([str(probe),str(calibration)],env=env,capture_output=True,text=True,timeout=30)
        report['phases']['run_calibration']=result.returncode
        need(result.returncode==0,'Calibration failed: '+result.stderr[-4000:])
        report['calibration']=verify_calibration(calibration);save(STATE,report)
        run('build_daemon',['build','--frozen','--release','-p','uvm-ublk-daemon','--features','overlaybd/rootfs-read-trace'])
        candidate=work/'candidate';candidate.mkdir();binary=candidate/'uvm-ublk-daemon-observe'
        with (CACHE/'target/release/uvm-ublk-daemon').open('rb') as src,binary.open('xb') as dst:shutil.copyfileobj(src,dst)
        os.chmod(binary,0o700)
        with binary.open('rb') as f:
            header=f.read(20);need(header[:6]==b'\x7fELF\x02\x01' and struct.unpack('<H',header[18:20])[0]==183,'Candidate is not ARM64 ELF')
            f.seek(0);h=hashlib.sha256()
            while chunk:=f.read(1024**2):h.update(chunk)
            digest=h.hexdigest()
        data=binary.read_bytes()
        need(PATCH_SHA.encode() in data and b'ROOTFS_ACCESS_OBSERVER_DISABLED' in data,'Shared-cache artifact does not attest this observer patch')
        report.update(status='ROOTFS_ACCESS_OBSERVER_BUILT_AND_CALIBRATED_NOT_DEPLOYED',candidate=str(binary),candidate_sha256=digest,
            next_action='Return this report; do not replace installed binaries or restart services manually.')
    except BaseException as e:
        report.update(status='STOPPED_ROOTFS_ACCESS_BUILD',error_type=type(e).__name__,reason=str(e))
    finally:
        save(STATE,report);save(work/'return.json',report);os.close(lock)
    print('BEGIN_RETURN_REPORT');print(json.dumps(report,indent=2));print('END_RETURN_REPORT')
    return 0 if report['status']=='ROOTFS_ACCESS_OBSERVER_BUILT_AND_CALIBRATED_NOT_DEPLOYED' else 1
