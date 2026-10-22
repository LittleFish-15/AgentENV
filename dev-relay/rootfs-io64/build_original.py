"""Build an original-only rootfs I/O limit candidate using verified cached sources.

INPUTS/DELTAS/PATCH_SHA are generated from the already-calibrated public packet.
No installed executable is overwritten, no service or Guest is touched here.
"""
import base64,hashlib,json,os,re,shutil,signal,stat,struct,subprocess,time
from pathlib import Path
ROOT=Path('/home/jwk/agent')
PREVIOUS=ROOT/'relay/reports/node-a-rootfs-access-build-abcks95d/source'
CACHE=ROOT/'builds/agentenv-ub-build-v2'
RUST=ROOT/'toolchains/agentenv-rust-1.99.0/rustup/toolchains/1.99.0-aarch64-unknown-linux-gnu/bin'


def need(ok,why):
    if not ok:raise RuntimeError(why)


def stage(source,previous=PREVIOUS):
    count=total=0
    for name,expected in sorted(INPUTS.items()):
        relative=Path(name);need(not relative.is_absolute() and '..' not in relative.parts and '\\' not in name,'Invalid compiler input path')
        old=previous/relative;need(old.resolve(strict=True)==old,'Redirected compiler input')
        meta=old.stat();need(stat.S_ISREG(meta.st_mode) and meta.st_size<=16*1024**2,'Unexpected compiler input')
        raw=old.read_bytes();need(hashlib.sha256(raw).hexdigest()==expected['sha256'],'Existing compiler source changed: '+name)
        if name in DELTAS:
            raw=base64.b64decode(DELTAS[name]['base64'],validate=True)
            need(hashlib.sha256(raw).hexdigest()==DELTAS[name]['sha256'],'Core delta differs')
        target=source/relative;target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('xb') as f:f.write(raw)
        os.chmod(target,0o700 if expected['executable'] else 0o600)
        count+=1;total+=len(raw);need(total<100*1024**2,'Source copy exceeds bound')
    return {'files':count,'bytes':total,'previous_source_modified':False,'network_source_download':False}


def calibration(directory):
    v=json.loads((directory/'calibration-input.json').read_bytes());key=(v['dev'],v['inode'])
    files={key:{'path':v['fixture'],'file_bytes':v['file_bytes']}}
    bindings={v['source'+str(i)]:{'sandbox_id':str(i),'template_id':'calibration','lower_keys':{key},'upper_keys':set()} for i in (1,2)}
    windows={str(i):(v['start_ns'],v['end_ns']) for i in (1,2)}
    status=json.loads((directory/'trace.status.json').read_bytes())
    with (directory/'trace.jsonl').open() as f:sets,audit=ACCOUNTING.read_sets(f,status,bindings,windows,files,PATCH_SHA)
    need(audit['records_checked']==3,'Calibration trace count differs')
    resident,probe=ACCOUNTING.resident_accessed_pages(files,sets['1']|sets['2'])
    measured=ACCOUNTING.pair_statistics(sets['1'],sets['2'],resident)
    need(measured['sandbox1_accessed_lower_bytes']==measured['sandbox2_accessed_lower_bytes']==8192,'Calibration reader attribution differs')
    need(measured['shared_accessed_host_pagecache_bytes']==4096 and measured['accessed_resident_union_bytes']==12288,'Calibration overlap differs')
    full={(key[0],key[1],i) for i in range(v['file_bytes']//4096)}
    all_resident,_=ACCOUNTING.resident_accessed_pages(files,full);need(all_resident==full,'Calibration fixture not fully resident')
    spec=(directory/'probe.access-spec').read_text();need('max_bytes=1048576\n' in spec,'Original calibration budget differs')
    return {'status':'ORIGINAL_OBSERVER_CALIBRATION_PASSED','configured_log_limit_bytes':1048576,
            'whole_fixture_resident_bytes':len(full)*4096,'measurement':measured,'audit':audit,'sampler':probe,
            'Guest_created':False,'SDK_called':False}


def build(work,persist):
    build_dir=work/'build';build_dir.mkdir(mode=0o700);source=build_dir/'source';source.mkdir()
    result={'status':'BUILDING_ORIGINAL_ROOTFS_IO64_CANDIDATES','phases':{},'patch_sha256':PATCH_SHA,'base_commit':'ae9c62693839ce7effa2b45df31c0039ae4f9fbc','dependency_mode':'frozen_offline_existing_cache',
            'installed_binaries_modified':False,'services_modified':False,'SDK_called':False,'Guest_created':False}
    def save():
        persist(result)
        tmp=build_dir/'return.tmp';tmp.write_text(json.dumps(result,indent=2));os.replace(tmp,build_dir/'return.json')
    try:
        save();print('PHASE=verify_and_reuse_existing_observer_sources',flush=True)
        result['source_reuse']=stage(source);save()
        for p in (CACHE/'cargo',CACHE/'target',RUST/'rustc',RUST/'cargo'):
            need(p.resolve(strict=True)==p and p.exists(),'Existing build input absent/redirected')
        result['rustc']=subprocess.check_output([str(RUST/'rustc'),'-V'],text=True,timeout=15).strip()
        need(result['rustc'].startswith('rustc 1.99.0 '),'Existing compiler differs')
        env=dict(os.environ)
        for k in list(env):
            if k.startswith('GIT_') or k in ('RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','CARGO_BUILD_TARGET','LD_PRELOAD','LD_AUDIT'):env.pop(k,None)
        env.update(CARGO_HOME=str(CACHE/'cargo'),CARGO_TARGET_DIR=str(CACHE/'target'),RUSTC=str(RUST/'rustc'),RUSTDOC=str(RUST/'rustdoc'),
            PATH=str(RUST)+os.pathsep+env.get('PATH',''),CARGO_NET_OFFLINE='true',CARGO_BUILD_JOBS='4',CMAKE_BUILD_PARALLEL_LEVEL='4',
            CARGO_INCREMENTAL='0',CARGO_PROFILE_DEV_DEBUG='0',CARGO_PROFILE_TEST_DEBUG='0',GIT_TERMINAL_PROMPT='0',
            GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',AENV_OBSERVER_BUILD_PATCH_SHA=PATCH_SHA)
        for variable,name in [('TMPDIR','tmp'),('XDG_CACHE_HOME','cache'),('XDG_CONFIG_HOME','config'),('XDG_STATE_HOME','state')]:
            p=build_dir/name;p.mkdir();env[variable]=str(p)
        if Path('/usr/lib64/libclang.so').is_file():env['LIBCLANG_PATH']='/usr/lib64'
        if shutil.which('protoc'):env['PROTOC']=shutil.which('protoc')
        config=build_dir/'offline.toml';config.write_text('[net]\noffline = true\n')
        def run(name,args,timeout=1800):
            print('PHASE='+name,flush=True);start=last=time.monotonic();log=build_dir/(name+'.log')
            with log.open('xb') as out:
                p=subprocess.Popen(args,cwd=source,env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=subprocess.STDOUT,start_new_session=True)
                try:
                    while p.poll() is None:
                        time.sleep(1);need(time.monotonic()-start<timeout,'Own build phase deadline')
                        if time.monotonic()-last>=30:
                            print('BUILD_HEARTBEAT phase='+name+' elapsed_seconds='+str(round(time.monotonic()-start)),flush=True);last=time.monotonic()
                except BaseException:
                    if p.poll() is None:
                        os.killpg(p.pid,signal.SIGTERM)
                        try:p.wait(timeout=15)
                        except subprocess.TimeoutExpired:result['own_build_process_group_exit_unconfirmed']=p.pid
                    raise
                result['phases'][name]=p.returncode
                if p.returncode:
                    with log.open('rb') as f:f.seek(max(0,log.stat().st_size-16000));tail=f.read().decode(errors='replace')
                    result['failure_log_tail']=re.sub(r'e2b_[A-Za-z0-9._~-]+','[REDACTED]',tail)
                save();need(p.returncode==0,name+' failed; inspect bounded log tail')
        cargo=[str(RUST/'cargo'),'--config',str(config)]
        run('test_daemon_io_limit',cargo+['test','--frozen','-p','uvm-ublk-daemon','--lib','io_limit','--','--test-threads=1'])
        run('test_pool_resize_matching',cargo+['test','--frozen','-p','uvm-ublk-daemon','--lib','idle_device_size_matching','--','--test-threads=1'])
        run('test_original_rootfs_config',cargo+['test','--frozen','-p','agentenv','--lib','rootfs_io_limit','--','--test-threads=1'])
        run('test_observer',cargo+['test','--frozen','-p','overlaybd','--features','io-uring,rootfs-read-trace','--lib','rootfs_access_trace::','--','--test-threads=1'])
        run('build_calibration',cargo+['build','--frozen','--release','-p','overlaybd','--features','io-uring,rootfs-read-trace','--example','rootfs_access_calibration'])
        cal=build_dir/'calibration';cal.mkdir(mode=0o700);probe=cal/'probe'
        with (CACHE/'target/release/examples/rootfs_access_calibration').open('rb') as src,probe.open('xb') as dst:shutil.copyfileobj(src,dst)
        os.chmod(probe,0o700);need(PATCH_SHA.encode() in probe.read_bytes(),'Calibration executable fingerprint differs')
        run('run_calibration',[str(probe),str(cal)],30);result['calibration']=calibration(cal);save()
        run('build_daemon',cargo+['build','--frozen','--release','-p','uvm-ublk-daemon','--features','overlaybd/rootfs-read-trace'])
        run('build_original_server',cargo+['build','--frozen','--release','-p','agentenv','--bin','server','--features','overlaybd/rootfs-read-trace'],3600)
        directory=work/'observer';directory.mkdir(mode=0o700);binary=directory/'uvm-ublk-daemon-observe'
        with (CACHE/'target/release/uvm-ublk-daemon').open('rb') as src,binary.open('xb') as dst:shutil.copyfileobj(src,dst)
        os.chmod(binary,0o700);raw=binary.read_bytes()
        need(raw[:6]==b'\x7fELF\x02\x01' and struct.unpack('<H',raw[18:20])[0]==183,'Candidate is not ARM64 ELF')
        need(PATCH_SHA.encode() in raw and b'ROOTFS_ACCESS_OBSERVER_DISABLED' in raw,'Candidate fingerprint differs')
        need(b'create_overlaybd_runtime_device_with_io_limit' in raw and b'kernel ublk I/O limit mismatch' in raw,'Daemon I/O extension absent')
        server=directory/'server-rootfs-io64'
        with (CACHE/'target/release/server').open('rb') as src,server.open('xb') as dst:shutil.copyfileobj(src,dst)
        os.chmod(server,0o700);server_raw=server.read_bytes()
        need(server_raw[:6]==b'\x7fELF\x02\x01' and struct.unpack('<H',server_raw[18:20])[0]==183,'Server is not ARM64 ELF')
        need(b'rootfs_max_io_kib' in server_raw and b'create_overlaybd_runtime_device_with_io_limit' in server_raw,'Server I/O extension absent')
        result.update(status='ORIGINAL_ROOTFS_IO64_BUILT_AND_CALIBRATED_NOT_DEPLOYED',candidate=str(binary),candidate_sha256=hashlib.sha256(raw).hexdigest(),server_candidate=str(server),server_sha256=hashlib.sha256(server_raw).hexdigest(),core_commit=CORE_COMMIT,rootfs_io_kib_for_experiment=64,default_io_kib=256,UB_code_included=False,next_action='Return this build report. Both candidates are staged only; do not replace or restart services manually.')
    except BaseException as e:
        result.update(status='STOPPED_ORIGINAL_ROOTFS_IO64_BUILD',error_type=type(e).__name__,reason=str(e));save();raise
    save();return result
