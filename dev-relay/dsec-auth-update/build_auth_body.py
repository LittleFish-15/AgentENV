"""Build only the pmem-ID Runtime fix using retained offline inputs on node A.

No services, API calls, SDK, Guests, image exports or kernel operations. Copy only
the exact tracked source inventory into a new directory; preserve the old build.
"""
import argparse,base64,hashlib,json,os,shutil,socket,stat,subprocess,sys,tomllib,zlib
from pathlib import Path,PurePosixPath
ROOT=Path('/home/jwk/agent')
OLD=ROOT/'builds/dsec-hostfile-release-v2'
WORK=ROOT/'builds/dsec-auth-order-fix-v1'
HELPER_SHA='424ddd4cb3edc36f52b79081fedbfda67fed569578df0d7a323824611d94e048'
RELEASE={}
OLD_BUILD={}
SOURCE_FILES={}
REPLACEMENTS={}
CONTRACT_FILES={}
CAPTURE_WRAPPER={}

def need(ok,reason):
    if not ok:raise RuntimeError(reason)

def read(path,limit=2*1024**2):
    need(path.resolve(strict=True)==path and path.is_relative_to(ROOT),'Redirected build input')
    with path.open('rb') as stream:
        before=os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid==1204 and 0<before.st_size<=limit,'Unexpected build input metadata')
        raw=stream.read(limit+1);after=os.fstat(stream.fileno())
    stamp=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    need(stamp(before)==stamp(after) and len(raw)==before.st_size,'Build input changed')
    return raw

def unpack(row):
    raw=zlib.decompress(base64.b64decode(row['z64'],validate=True))
    need(len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256'],'Embedded source differs')
    return raw

def copy_source():
    source=WORK/'source';source.mkdir(mode=0o700)
    old=OLD/'core-source/agentenv-native-core'
    total=0
    for relative,row in SOURCE_FILES.items():
        parts=PurePosixPath(relative)
        need(not parts.is_absolute() and '..' not in parts.parts,'Invalid source entry')
        raw=read(old/relative,4*1024**2)
        need(hashlib.sha256(raw).hexdigest()==row['oldSha256'],'Retained source changed: '+relative)
        if relative in REPLACEMENTS:raw=unpack(REPLACEMENTS[relative])
        need(hashlib.sha256(raw).hexdigest()==row['newSha256'],'Candidate source differs: '+relative)
        total+=len(raw);need(total<=32*1024**2,'Source budget exceeded')
        target=source/relative;target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        with target.open('xb') as out:out.write(raw)
        target.chmod(0o700 if row['executable'] else 0o600)
    return source,total

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run',action='store_true');args=parser.parse_args()
    report={'status':'PLAN_ONLY','release':RELEASE,'workDirectory':str(WORK),'phases':{},
        'SDK_called':False,'Guest_created':False,'servicesChanged':False,'coreSourceFiles':len(SOURCE_FILES),
        'rebuiltComponents':['server'],'retainedComponents':['firecracker','aenv-native-fd-verify','aenv','uvm-ublk-daemon'],
        'scope':'Runtime resource-ID fix build, not Guest or physical-sharing acceptance'}
    if not args.run:print(json.dumps(report,indent=2));return 0
    made=False
    try:
        need(sys.platform=='linux' and os.uname().machine=='aarch64' and socket.gethostname()=='server1','Use A ARM64')
        need(os.getuid()==os.geteuid()==1204 and os.getgid()==os.getegid()==1205,'Use ordinary jwk')
        caps=dict(x.split(':',1) for x in Path('/proc/self/status').read_text().splitlines() if ':' in x)
        need(all(int(caps[x],16)==0 for x in ('CapInh','CapPrm','CapEff','CapAmb')),'Capability-free build required')
        need(not WORK.exists() and not WORK.is_symlink() and WORK.parent.resolve(strict=True)==WORK.parent,'Prior build preserved')
        old=json.loads(read(OLD/'return.json'))
        for key in ('status','release','artifacts','embeddedPolicySha256'):
            need(old.get(key)==OLD_BUILD[key],'Retained completed build differs: '+key)
        need(set(old.get('phases',{}))==set(OLD_BUILD['phases']) and all(x.get('exitCode')==0 for x in old['phases'].values()),'Prior tests/build incomplete')
        for name,row in old['artifacts'].items():
            need(row['path']==str(OLD/'artifacts'/name),'Unexpected retained artifact path')
            raw=read(OLD/'artifacts'/name,128*1024**2)
            need(len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256'],'Retained artifact changed')
        helper=ROOT/'A_export_real_rootfs_v1.py';raw=read(helper)
        need(hashlib.sha256(raw).hexdigest()==HELPER_SHA,'Existing offline helper changed')
        m={'__name__':'verified_build_helpers'};exec(compile(raw,str(helper),'exec'),m)
        need(shutil.disk_usage(ROOT).free>=16*1024**3,'Need 16GiB build reserve; do not remove existing files')
        os.umask(0o077);WORK.mkdir(mode=0o700);made=True;(WORK/'tmp').mkdir(mode=0o700)
        m['WORK']=WORK
        print('PHASE=verify-and-copy-exact-source-inventory',flush=True)
        source,total=copy_source();report['sourceBytes']=total
        frozen=read(source/'Cargo.lock')
        need(hashlib.sha256(frozen).hexdigest()==m['LOCK_SHA'],'Frozen dependencies differ')
        rust=m['RUST'];native=m['BASE']/'native'
        env={'HOME':str(Path.home()),'USER':'jwk','LOGNAME':'jwk','LANG':'C.UTF-8',
            'PATH':str(rust)+':'+str(native/'bin')+':/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin',
            'CARGO_HOME':str(m['CARGO_HOME']),'CARGO_TARGET_DIR':str(m['TARGET']),'CARGO_NET_OFFLINE':'true',
            'CARGO_BUILD_JOBS':'2','CARGO_INCREMENTAL':'0','RUSTC':str(rust/'rustc'),'RUSTDOC':str(rust/'rustdoc'),
            'CARGO_PROFILE_RELEASE_LTO':'false','CARGO_PROFILE_RELEASE_DEBUG':'0','LIBCLANG_PATH':'/usr/lib64',
            'CMAKE_BUILD_PARALLEL_LEVEL':'2','PROTOC':'/usr/local/bin/protoc','TMPDIR':str(WORK/'tmp'),
            'LD_LIBRARY_PATH':str(native/'lib')+':'+str(native/'fallback/lib'),
            'GIT_TERMINAL_PROMPT':'0','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':os.devnull,
            'GIT_CEILING_DIRECTORIES':str(WORK)}
        pkg_dirs=[p for p in (native/'lib/pkgconfig',ROOT/'native/lib64/pkgconfig') if p.is_dir()]
        if pkg_dirs:env['PKG_CONFIG_PATH']=':'.join(map(str,pkg_dirs))
        prior=json.loads(read(ROOT/'builds/agentenv-native-fe63038/return.json'))
        need(prior.get('status')=='THREE_CORE_BINARIES_BUILT_STAGED_NOT_DEPLOYED','Native dependency provenance missing')
        for key,patterns in (('ROCKSDB_LIB_DIR',('librocksdb.*',)),('SNAPPY_LIB_DIR',('libsnappy.*',)),
                             ('LIBCLANG_PATH',('libclang.so*','libclang-*.so*'))):
            value=prior.get('explicitNativeBuildDirectories',{}).get(key)
            if value:
                directory=Path(value)
                need(directory.is_absolute() and directory.resolve(strict=True)==directory and directory.is_dir()
                     and any(any(directory.glob(pattern)) for pattern in patterns),'Prior native dependency changed: '+key)
                env[key]=str(directory)
        cargo=rust/'cargo'
        tests=WORK/'readiness-order-contract';tests.mkdir(mode=0o700)
        for name,row in CONTRACT_FILES.items():
            need(name in ('Cargo.toml','lib.rs','pmem.rs'),'Unexpected contract source')
            with (tests/name).open('xb') as out:out.write(unpack(row))
        (tests/'Cargo.lock').write_bytes(frozen)
        m['run']([cargo,'metadata','--offline','--format-version','1','--manifest-path',str(tests/'Cargo.toml')],
                 'resolve-readiness-order-contract',tests,env,report,120)
        registry=lambda b:{(p['name'],p['version'],p.get('source'),p.get('checksum')) for p in tomllib.loads(b.decode()).get('package',[]) if p.get('source')}
        need(registry(read(tests/'Cargo.lock'))<=registry(frozen),'Contract test dependency drift')
        m['run']([cargo,'test','--release','--offline','--locked','--manifest-path',str(tests/'Cargo.toml'),'--lib'],
                 'test-readiness-order-contract',tests,env,report)
        artifacts=WORK/'artifacts';artifacts.mkdir(mode=0o700)
        target=artifacts/'server'
        wrapper=unpack(CAPTURE_WRAPPER).decode()
        need(wrapper.count('CONFIG={}\n')==1,'Compiler capture source changed')
        wrapper=wrapper.replace('CONFIG={}\n','CONFIG='+repr({'source':str(source),'target':str(m['TARGET']),
            'rustc':str(rust/'rustc'),'destination':str(target),'receipt':str(WORK/'captured-server.json')})+'\n')
        wrapper_path=WORK/'capture-rustc.py';wrapper_path.write_text(wrapper);wrapper_path.chmod(0o750)
        env['RUSTC_WRAPPER']=str(wrapper_path)
        m['run']([cargo,'build','--release','--offline','--locked','-p','agentenv','--bin','server'],
                 'build-fixed-runtime',source,env,report)
        captured=json.loads(read(WORK/'captured-server.json'))
        need(captured.get('capturedBeforeRustcWrapperExit') is True and captured.get('path')==str(target)
             and captured.get('sourceManifest')==str(source/'Cargo.toml'),'No captured candidate provenance')
        candidate=read(target,128*1024**2)
        need(candidate[:6]==b'\x7fELF\x02\x01' and candidate[18:20]==b'\xb7\x00','Candidate is not AArch64 ELF')
        need(len(candidate)==captured['bytes'] and hashlib.sha256(candidate).hexdigest()==captured['sha256'],
             'Captured candidate changed')
        report.update(status='DSEC_AUTH_RUNTIME_BUILT_TESTED_NOT_DEPLOYED',
            server={'path':str(target),'bytes':len(candidate),'sha256':hashlib.sha256(candidate).hexdigest()},
            captureProvenance=captured,
            retainedArtifacts={k:v for k,v in old['artifacts'].items() if k!='server'},
            retainedCoreCommit=old['release']['coreCommit'],embeddedPolicySha256=old['embeddedPolicySha256'])
    except Exception as error:
        report.update(status='STOPPED_PMEM_ID_BUILD_PRESERVE_ALL_OUTPUTS',errorType=type(error).__name__,reason=str(error)[:1500])
    if made:
        with (WORK/'return.json').open('x') as out:json.dump(report,out,indent=2)
    print('BEGIN_PMEM_ID_BUILD_REPORT');print(json.dumps(report,indent=2));print('END_PMEM_ID_BUILD_REPORT')
    return 0 if report['status']=='DSEC_AUTH_RUNTIME_BUILT_TESTED_NOT_DEPLOYED' else 1

if __name__=='__main__':raise SystemExit(main())
