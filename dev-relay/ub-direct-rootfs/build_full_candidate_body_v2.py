"""Native tests and linked artifacts for the actual required-UB aenv Runtime.

Reuses retained offline toolchains/cache. Does not call SDK, start Guests or
change services/kernel. The previous Host provider experiment is not acceptance.
"""
import argparse,base64,hashlib,json,os,re,shutil,stat,subprocess,sys,zlib
from pathlib import Path,PurePosixPath
ROOT=Path('/home/jwk/agent')
OLD=ROOT/'builds/direct-ub-runtime-core-v2/source'
WORK=ROOT/'builds/full-ub-runtime-candidate-v2'
HELPER_SHA='424ddd4cb3edc36f52b79081fedbfda67fed569578df0d7a323824611d94e048'


def need(ok,message):
    if not ok:raise RuntimeError(message)


def read(path,limit=4*1024**2):
    path=Path(path)
    need(path.is_relative_to(ROOT) and path.resolve(strict=True)==path,'Unexpected/redirected input')
    with path.open('rb') as stream:
        m=os.fstat(stream.fileno())
        need(stat.S_ISREG(m.st_mode) and m.st_uid==1204 and m.st_size<=limit,'Input owner/type/size differs')
        data=stream.read(limit+1);n=os.fstat(stream.fileno())
        need((m.st_dev,m.st_ino,m.st_size,m.st_mtime_ns,m.st_ctime_ns)==
             (n.st_dev,n.st_ino,n.st_size,n.st_mtime_ns,n.st_ctime_ns),'Input changed during read')
    return data


def unpack(value):
    raw=zlib.decompress(base64.b64decode(value['z64'],validate=True))
    need(len(raw)==value['bytes'] and hashlib.sha256(raw).hexdigest()==value['sha256'],'Embedded source changed')
    return raw


def sources():
    destination=WORK/'source';destination.mkdir(mode=0o700)
    total=0
    for name,row in SOURCE_FILES.items():
        path=PurePosixPath(name)
        need(not path.is_absolute() and '..' not in path.parts,'Invalid source path')
        if name in REPLACEMENTS:raw=unpack(REPLACEMENTS[name])
        else:
            raw=read(OLD/name)
            need(hashlib.sha256(raw).hexdigest()==row['oldSha256'],'Retained source changed: '+name)
        need(hashlib.sha256(raw).hexdigest()==row['newSha256'],'Candidate source changed: '+name)
        total+=len(raw);need(total<=32*1024**2,'Source inventory exceeds budget')
        target=destination/name;target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        with target.open('xb') as output:output.write(raw)
        target.chmod(0o700 if row['executable'] else 0o600)
    return destination,total


def progress(report):
    temporary=WORK/'build-progress.next.json'
    with temporary.open('x',encoding='utf-8') as output:
        json.dump(report,output,indent=2);output.flush();os.fsync(output.fileno())
    os.replace(temporary,WORK/'build-progress.json')
    fd=os.open(WORK,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


def check_full_artifacts():
    pins={'server':'759423e634e25bc2e74067bfaccc16e40720907fc0e717269261dd573f0097df',
          'uvm-ublk-daemon':'8bd4952d2c0f524f73bd51b4a4635c3b2af66dfe5af23b94dbfd4d5a6195a17d'}
    result={}
    for directory in (OLD.parent/'artifacts',ROOT/'deployments/agentenv-direct-ub-guest-v1/bin'):
        for name,pin in pins.items():
            path=directory/name;data=read(path,128*1024**2)
            need(hashlib.sha256(data).hexdigest()==pin,'Retained full artifact differs: '+name)
            m=path.stat();result[str(path)]={'sha256':pin,'bytes':len(data),'dev':m.st_dev,'inode':m.st_ino,'mtimeNs':m.st_mtime_ns}
    return result


def no_local_guests():
    # Read-only local process guard. It does not prove the peer is idle.
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():continue
        try:
            if (proc/'comm').read_text().strip()!='firecracker':continue
            status=(proc/'status').read_text()
            match=re.search(r'(?m)^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$',status)
            need(match is not None,'Cannot identify Firecracker user; preserve build inputs')
            need(1204 not in [int(value) for value in match.groups()],
                 'Local jwk Guest is active; do not compile during comparison')
        except (FileNotFoundError,ProcessLookupError):continue


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run',action='store_true');a=parser.parse_args()
    report={'status':'PLAN_ONLY','release':RELEASE,'workDirectory':str(WORK),'phases':{},
        'SDK_called':False,'Guest_created':False,'servicesChanged':False,'kernelChanged':False,
        'buildRequestedComponents':['server','uvm-ublk-daemon'],'rebuiltComponents':[],'retainedComponents':['aenv','firecracker','kernel','tools'],
        'scope':'independent full UB Runtime candidate build; no deployment or UB/Guest acceptance',
        'fullPreserved':False,'fullPreservationScope':'A captured and deployed server/daemon; B not observed',
        'sharedDependencyTargetUsed':False,'unchangedFullProviderDirectIORechecked':False,
        'rootfsReadTraceRequested':True,'rootfsReadTraceCompiled':False,'twoNodeGuestAccepted':False,'netSavingsBytes':None}
    if not a.run:print(json.dumps(report,indent=2));return 0
    made=False
    try:
        need(sys.platform=='linux' and os.uname().machine=='aarch64' and os.uname().nodename=='server1','Build on A ARM64')
        need(os.getuid()==os.geteuid()==1204 and os.getgid()==os.getegid()==1205,'Use ordinary jwk')
        caps=[line.split()[1] for line in Path('/proc/self/status').read_text().splitlines()
              if line.startswith(('CapInh:','CapPrm:','CapEff:','CapAmb:'))]
        need(len(caps)==4 and not any(int(x,16) for x in caps),'Zero capabilities required')
        need(not WORK.exists() and not WORK.is_symlink() and WORK.parent.resolve(strict=True)==WORK.parent,'Prior build preserved')
        previous_bytes=read(OLD.parent/'return.json')
        previous=json.loads(previous_bytes)
        need(previous.get('status')=='DIRECT_UB_RUNTIME_AND_DAEMON_BUILT_TESTED_NOT_DEPLOYED'
             and previous.get('release',{}).get('coreCommit')=='ff1efdd9a2598e19b84cc09b91c8bc1e10ab6254',
             'Expected preserved full build receipt missing')
        need(all(previous.get(key) is False for key in ('SDK_called','Guest_created','servicesChanged','kernelChanged')),
             'Prior full build scope differs')
        report['preservedFullReceiptSha256']=hashlib.sha256(previous_bytes).hexdigest()
        no_local_guests()
        full_before=check_full_artifacts()
        helper=ROOT/'A_export_real_rootfs_v1.py';raw=read(helper)
        need(hashlib.sha256(raw).hexdigest()==HELPER_SHA,'Existing offline build helper changed')
        m={'__name__':'pinned_offline_build_helpers'};exec(compile(raw,str(helper),'exec'),m)
        need(shutil.disk_usage(ROOT).free>=24*1024**3,'Need 24GiB build reserve; no cleanup attempted')
        os.umask(0o077);WORK.mkdir(mode=0o700);made=True;(WORK/'tmp').mkdir(mode=0o700)
        report['status']='FULL_UB_CANDIDATE_NATIVE_BUILD_RUNNING'
        m['WORK']=WORK
        m['TARGET']=WORK/'target'
        m['TARGET'].mkdir(mode=0o700)
        run_phase=m['run']
        def tracked_run(command,name,cwd,environment,current_report):
            current_report['pendingPhase']=name
            progress(current_report)
            try:
                result=run_phase(command,name,cwd,environment,current_report)
                current_report.pop('pendingPhase',None)
                return result
            finally:
                progress(current_report)
        m['run']=tracked_run

        source,total=sources();report['sourceBytes']=total
        need(hashlib.sha256(read(source/'Cargo.lock')).hexdigest()==m['LOCK_SHA'],'Frozen Cargo dependencies differ')
        rust=m['RUST'];native=m['BASE']/'native';cargo=rust/'cargo'
        env={'HOME':'/home/jwk','USER':'jwk','LOGNAME':'jwk','LANG':'C.UTF-8',
             'PATH':str(rust)+':'+str(native/'bin')+':/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin',
             'CARGO_HOME':str(m['CARGO_HOME']),'CARGO_TARGET_DIR':str(m['TARGET']),
             'CARGO_NET_OFFLINE':'true','CARGO_BUILD_JOBS':'2','CARGO_INCREMENTAL':'0',
             'AENV_BUILD_GIT_COMMIT':RELEASE['coreCommit'],
             'RUSTC':str(rust/'rustc'),'RUSTDOC':str(rust/'rustdoc'),
             'CARGO_PROFILE_RELEASE_LTO':'false','CARGO_PROFILE_RELEASE_DEBUG':'0',
             'CMAKE_BUILD_PARALLEL_LEVEL':'2','LIBCLANG_PATH':'/usr/lib64','PROTOC':'/usr/local/bin/protoc',
             'TMPDIR':str(WORK/'tmp'),'LD_LIBRARY_PATH':str(native/'lib')+':'+str(native/'fallback/lib'),
             'GIT_TERMINAL_PROMPT':'0','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':os.devnull,
             'GIT_CEILING_DIRECTORIES':str(WORK)}
        pkg=[str(p) for p in (native/'lib/pkgconfig',ROOT/'native/lib64/pkgconfig') if p.is_dir()]
        if pkg:env['PKG_CONFIG_PATH']=':'.join(pkg)
        prior=json.loads(read(ROOT/'builds/agentenv-native-fe63038/return.json'))
        need(prior.get('status')=='THREE_CORE_BINARIES_BUILT_STAGED_NOT_DEPLOYED','Native dependency provenance missing')
        for key,patterns in (('ROCKSDB_LIB_DIR',('librocksdb.*',)),('SNAPPY_LIB_DIR',('libsnappy.*',)),
                             ('LIBCLANG_PATH',('libclang.so*','libclang-*.so*'))):
            value=prior.get('explicitNativeBuildDirectories',{}).get(key)
            if value:
                directory=Path(value)
                need(directory.is_absolute() and directory.resolve(strict=True)==directory
                     and any(any(directory.glob(pattern)) for pattern in patterns),'Retained dependency changed: '+key)
                env[key]=str(directory)
        # Only new metadata planning/composition tests; unchanged full-provider
        # direct-I/O and Host full-read experiments are not repeated here.
        no_local_guests()
        name='provider-full-set-tests'
        m['run'](['/usr/bin/python3','-I','-B','-m','unittest','discover','-s','tests',
                  '-p','test_full_set.py','-v'],name,source/'components/ub-memory-provider',env,report)
        output=read(WORK/(name+'.log'),16*1024**2).decode('utf-8','replace')
        required=('test_only_missing_content_is_published',
            'test_budget_shortfall_does_not_emit_publication_or_runtime_index',
            'test_composition_keeps_both_actual_brokers_and_owner_lifetimes',
            'test_node_local_socket_differences_do_not_change_shared_content_identity',
            'test_missing_duplicate_or_unregistered_generation_is_refused',
            'test_replacing_old_object_or_enabling_fallback_is_refused')
        need(all(any(test in line and line.rstrip().endswith('... ok') for line in output.splitlines())
                 for test in required),'Required full-set metadata tests did not execute/pass')
        for name,filter_name in (('native-ub-wire-and-lease-tests','backend::ub'),
                                 ('native-ub-binding-tests','config::ub_tests')):
            no_local_guests()
            m['run']([cargo,'test','--release','--offline','--locked','-p','overlaybd',
                '--features','io-uring,rootfs-read-trace','--lib',filter_name],name,source,env,report)
            output=read(WORK/(name+'.log'),16*1024**2).decode('utf-8','replace')
            required=(('failed_incarnation_cannot_reconnect_even_after_last_file_drops',
                       'runtime_permits_outlive_one_guest_and_keep_broker_session_open',
                       'shared_session_holds_readers_and_exports_exact_durable_bytes',
                       'failed_second_chunk_rereads_the_entire_verified_fallback_range',
                       'open_frame_has_exact_v1_layout_without_trailing_bytes',
                       'runtime_permits_hold_each_full_set_broker_until_last_guest',
                       'full_set_missing_broker_does_not_leak_partial_runtime_permits')
                      if filter_name=='backend::ub' else ('strict_rootfs_index_pins_generation_and_refuses_fallback',
                            'ub_bind_is_atomic_and_preserves_local_upper'))
            need(all(any(test in line and line.rstrip().endswith('... ok') for line in output.splitlines())
                     for test in required),'Required actual-core regression did not execute/pass')
        for name,filter_name,required in (
            ('native-ub-directory-retention-tests','ub_retention::tests',(
                'unresolved_directory_and_marker_survive_drop',
                'existing_marker_is_not_overwritten_and_directory_still_survives',
                'ordinary_temp_directory_still_cleans_up','unix_marker_is_owner_only')),
            ('native-failed-launch-ownership-tests','ub_failed_launch_',(
                'ub_failed_launch_and_failed_stop_retain_runtime_for_delete_retry',
                'ub_failed_launch_resume_stop_does_not_restore_paused_or_allow_resume',
                'ub_failed_launch_metadata_error_preserves_ownership_and_blocks_blind_delete',
                'ub_failed_launch_identity_conflict_retains_old_handle_without_replacing_new',
                'ub_failed_launch_shutdown_retries_retained_stop')),
            ('native-launch-rollback-regression','cleanup_failed_launch',(
                'cleanup_failed_launch_removes_created_running_metadata',
                'cleanup_failed_launch_restores_resume_metadata',
                'cleanup_failed_launch_does_not_remove_replacement_runtime_state')),
            ('native-delete-retry-regression','delete_when_stop_fails_returns_error_and_allows_retry',(
                'delete_when_stop_fails_returns_error_and_allows_retry',)),
        ):
            no_local_guests()
            m['run']([cargo,'test','--release','--offline','--locked','-p','agentenv',
                '--features','overlaybd/rootfs-read-trace','--lib',filter_name],name,source,env,report)
            output=read(WORK/(name+'.log'),16*1024**2).decode('utf-8','replace')
            need(all(any(test in line and line.rstrip().endswith('... ok') for line in output.splitlines())
                     for test in required),'Required lifecycle regression did not execute/pass')
        report['failedLaunchOwnershipNativeTestsPassed']=True
        report['unresolvedDirectoryNativeTestsPassed']=True
        artifacts=WORK/'artifacts';artifacts.mkdir(mode=0o700)
        report['artifacts']={};report['captureProvenance']={}
        for package,binary,crate,manifest_dir in (
            ('agentenv','server','server',source),
            ('uvm-ublk-daemon','uvm-ublk-daemon','uvm_ublk_daemon',source/'storage/ublk-daemon')):
            wrapper=unpack(CAPTURE_WRAPPER).decode()
            need(wrapper.count('CONFIG={}\n')==1,'Capture wrapper marker differs')
            wrapper=wrapper.replace('CONFIG={}\n','CONFIG='+repr({'source':str(manifest_dir),'target':str(m['TARGET']),
                'rustc':str(rust/'rustc'),'crate':crate,'destination':str(artifacts/binary),
                'receipt':str(WORK/('captured-'+binary+'.json'))})+'\n')
            wrapper_path=WORK/('capture-'+binary+'.py');wrapper_path.write_text(wrapper);wrapper_path.chmod(0o750)
            build_env=dict(env,RUSTC_WRAPPER=str(wrapper_path))
            no_local_guests()
            m['run']([cargo,'rustc','--release','--offline','--locked','-p',package,'--bin',binary,
                '--features','overlaybd/rootfs-read-trace','--','-C','metadata=full_ub_candidate_'+RELEASE['localCommit'][:12]+'_'+crate],
                'build-'+binary,source,build_env,report)
            captured=json.loads(read(WORK/('captured-'+binary+'.json')))
            candidate=read(artifacts/binary,128*1024**2)
            need(captured.get('capturedBeforeRustcWrapperExit') is True
                 and captured.get('sourceManifest')==str(manifest_dir/'Cargo.toml')
                 and len(candidate)==captured['bytes'] and hashlib.sha256(candidate).hexdigest()==captured['sha256'],
                 'Candidate artifact provenance differs')
            report['artifacts'][binary]={k:captured[k] for k in ('path','bytes','sha256')}
            report['captureProvenance'][binary]=captured
            report['rebuiltComponents'].append(binary)
        no_local_guests()
        retained=ROOT/'deployments/agentenv-lazy-four-32ce41c'
        inventory=json.loads(read(retained/'input-manifest.json'))
        report['retainedArtifacts']={}
        for name,path in (('aenv','bin/aenv'),('firecracker','deps/firecracker/1.15.1-patch-v3/firecracker'),
                          ('kernel','deps/kernel/vmlinux-6.1.175/vmlinux.bin'),('tools','deps/tools/0.1.1/tools.ext4')):
            data=read(retained/path,128*1024**2)
            need(hashlib.sha256(data).hexdigest()==inventory[path]['sha256'],'Retained dependency changed: '+name)
            report['retainedArtifacts'][name]={'path':str(retained/path),'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)}
        need(check_full_artifacts()==full_before,'Preserved full binary changed during full candidate build')
        report['preservedFullArtifacts']=full_before
        report['fullPreserved']=True
        adapter=ROOT/'r/ud-a-v1/libaenv-ub.so'
        raw=read(adapter,1024**2)
        need(hashlib.sha256(raw).hexdigest()=='bc53b2e010ebe3a0d69d3f64bad17afee5b7950d06b77d2803565222758ca6d5',
             'Retained SDK adapter differs; do not rebuild/replace implicitly')
        report['retainedSdkAdapter']={'path':str(adapter),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
        report['providerSource']=str(source/'components/ub-memory-provider')
        report['status']='FULL_UB_CANDIDATE_CORE_BUILT_TESTED_NOT_DEPLOYED'
        report['rootfsReadTraceCompiled']=True
    except Exception as error:
        report.update(status='STOPPED_FULL_UB_CANDIDATE_BUILD_PRESERVE_OUTPUTS',errorType=type(error).__name__,reason=str(error)[:2000])
    if made:
        with (WORK/'return.json').open('x') as output:json.dump(report,output,indent=2)
    print('BEGIN_FULL_UB_CANDIDATE_CORE_BUILD_REPORT');print(json.dumps(report,indent=2));print('END_FULL_UB_CANDIDATE_CORE_BUILD_REPORT')
    return 0 if report['status']=='FULL_UB_CANDIDATE_CORE_BUILT_TESTED_NOT_DEPLOYED' else 1


if __name__=='__main__':raise SystemExit(main())
