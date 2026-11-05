"""Bounded kernel-package and module inspection for the existing manual relay.

No installation, boot change, sysfs write, module load, service action or SDK call.
Only bounded diagnostic output is emitted; binary packages remain on the host.
"""
import hashlib,json,os,re,socket,subprocess,time
from pathlib import Path

RPM_NAME='kernel-6.6.0_sp3_tlbi3_1027+-28.aarch64.rpm'
def run(args,seconds=20,limit=100000):
    try:
        p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=seconds)
        return {'argv':args,'exitCode':p.returncode,'stdout':p.stdout[:limit].decode(errors='replace'),
                'stderr':p.stderr[:4000].decode(errors='replace'),'truncated':len(p.stdout)>limit}
    except subprocess.TimeoutExpired:return {'argv':args,'state':'TIMEOUT'}
    except OSError as e:return {'argv':args,'state':'UNAVAILABLE','error':str(e)}
def read(path,limit=100000):
    try:
        with open(path,'rb') as f:return f.read(limit).decode(errors='replace')
    except OSError:return None
def config(raw):
    if raw is None:return None
    return '\n'.join(x for x in raw.splitlines() if re.search(
        r'CONFIG_(KVM|KVM_ARM_DIRECT_TLBI|KVM_ARM_TLBI_IPI|ARM64_TLBI_IPI|ARM64_4K_PAGES|ARM64_64K_PAGES|HZ(?:_\d+)?|UBUS|.*UMMU.*|.*OBMM.*)(?:=| is not set)',x))
def package_config(path):
    a=b=None
    try:
        a=subprocess.Popen(['rpm2cpio',path],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        b=subprocess.Popen(['cpio','-i','--to-stdout','--quiet','*boot/config-*'],stdin=a.stdout,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        a.stdout.close();out,err=b.communicate(timeout=80);a.wait(timeout=5)
        if len(out)>2*1024**2:return {'state':'OUTPUT_TOO_LARGE'}
        return {'rpm2cpioExit':a.returncode,'cpioExit':b.returncode,'config':config(out.decode(errors='replace')),'stderr':err[:2000].decode(errors='replace')}
    except (OSError,subprocess.TimeoutExpired) as e:return {'state':'UNAVAILABLE','error':str(e)}
    finally:
        for p in (a,b):
            if p is not None and p.poll() is None:p.kill();p.wait()
def main():
    if os.geteuid()!=0:raise RuntimeError('Existing unified root entry required')
    if socket.gethostname()!='agent1':raise RuntimeError('This task is for registered node-b only')
    release=os.uname().release
    result={'state':'READONLY_INSPECTION','hostname':socket.gethostname(),'kernel':release,
        'architecture':os.uname().machine,'bootId':read('/proc/sys/kernel/random/boot_id'),
        'osRelease':read('/etc/os-release'),'cmdline':read('/proc/cmdline'),
        'runningConfig':config(read('/boot/config-'+release)),
        'runningParameters':{p:read('/sys/module/'+p+'/parameters/'+q) for p,q in
            [('arm64_tlbi_ipi','flags'),('kvm','direct_tlbi'),('kvm','tlbi_ipi')]},
        'currentModules':read('/proc/modules'),'bootSpace':run(['df','-h','/boot','/']),
        'defaultKernel':run(['grubby','--default-kernel']),
        'installedKernelPackages':run(['rpm','-qa','kernel*']),
        'services':run(['systemctl','list-units','--all','--no-pager','--plain','aenv*','*ubse*','*obmm*']),
        'firecrackerProcessIds':run(['pgrep','-x','firecracker']),
        'modules':{m:run(['modinfo',m]) for m in ('ubus','ummu-core','obmm')},
        'mutations':{'installed':False,'bootChanged':False,'rebooted':False,'parametersWritten':False,'SDKCalled':False}}
    roots=[x for x in ('/home','/root','/data','/opt','/tmp','/var/tmp') if Path(x).is_dir()]
    found=run(['find',*roots,'-maxdepth','6','-type','f','-name',RPM_NAME,'-print'],80,16000)
    result['packageSearch']=found
    candidates=found.get('stdout','').splitlines()
    result['packages']=[]
    for path in candidates[:2]:
        p=Path(path)
        if p.is_symlink() or not p.is_file() or p.name!=RPM_NAME:continue
        size=p.stat().st_size
        row={'path':path,'bytes':size}
        if size<=2*1024**3:
            h=hashlib.sha256();start=time.monotonic()
            with p.open('rb') as f:
                while True:
                    data=f.read(1024**2)
                    if not data:row['sha256']=h.hexdigest();break
                    h.update(data)
                    if time.monotonic()-start>40:row['hashState']='TIME_LIMIT';break
        row['metadata']=run(['rpm','-qp','--qf','%{NAME}\n%{VERSION}-%{RELEASE}\n%{ARCH}\n%{SOURCERPM}\n',path])
        row['signature']=run(['rpm','-Kv',path],40)
        row['requires']=run(['rpm','-qp','--requires',path])
        row['provides']=run(['rpm','-qp','--provides',path])
        row['scripts']=run(['rpm','-qp','--scripts',path])
        files=run(['rpm','-qpl',path]);listing=files.get('stdout','').splitlines()
        row['bootFiles']=[x for x in listing if x.startswith('/boot/')]
        row['driverFiles']=[x for x in listing if re.search(r'(obmm|ubus|ummu)',x,re.I)][:150]
        row['packageConfig']=package_config(path)
        result['packages'].append(row)
    result['patchesConfirmed']=False
    result['nextStep']='REVIEW_PACKAGE_SOURCE_AND_MATCHING_DRIVERS' if result['packages'] else 'RPM_NOT_FOUND_IN_BOUNDED_SEARCH_NEED_ACTUAL_PATH_OR_SCP'
    result['searchIsExhaustive']=False
    print(json.dumps(result,ensure_ascii=False,separators=(',',':')))
if __name__=='__main__':main()
