"""Fix only the block baseline ext4 mount option, keeping the failed run intact.
Default plan. --run reuses the already pinned comparison packet and prepares v2.
"""
import argparse,base64,hashlib,json,os,stat,sys,types
from pathlib import Path
ROOT=Path('/home/jwk/agent')
OLD=ROOT/'r/pm-a-v1/cache-compare-v1'
BUNDLE_SHA='f7294ddb13a76cc147a8958a80fa683d34a3e400916598b0cdb407b664f06384'
OLD_CONFIG_SHA='f8f91d25062b8d36993d8569cb1a5211c585401411dc931e168962a734c1020e'

def need(ok,reason):
    if not ok:raise RuntimeError(reason)

def read(path,limit):
    need(path.resolve(strict=True)==path,'Redirected input refused')
    with path.open('rb') as stream:
        before=os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid==1204 and 0<before.st_size<=limit,'Input owner/type/size differs')
        raw=stream.read(limit+1);after=os.fstat(stream.fileno())
    stamp=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)
    need(stamp(before)==stamp(after) and len(raw)==before.st_size,'Input changed')
    return raw

def validate_prior(report):
    need(report.get('status')=='PARTIAL_COMPONENT_DATA_REVIEW_FAILURE','Expected failed v1 run')
    need(report.get('unresolvedFCPids')==[] and report.get('wholeMatrixLeaseClosedAfterKnownFCExit') is True,'Prior FC/lease unresolved')
    groups=report.get('groups')
    need(isinstance(groups,list) and len(groups)==1,'Expected only the first block group')
    row=groups[0]
    need(row.get('mode')=='block' and row.get('N')==1 and row.get('accepted') is False
         and row.get('allFCReapedAndLeasesClosed') is True,'Unexpected prior group lifecycle')
    logs=row.get('failureLogs',[])
    need(len(logs)==1 and "ext4: Unknown parameter 'nodax'" in logs[0].get('serial.log',''), 'Expected exact ext4 option failure')

def prepare_module(raw):
    need(hashlib.sha256(raw).hexdigest()==BUNDLE_SHA,'Installed comparison bundle differs')
    source=raw.decode()
    need("stage=base/'cache-compare-v1'" in source,'Expected bounded stage definition')
    source=source.replace('cache-compare-v1','cache-compare-v2').replace('-v1.service','-v2.service')
    module=types.ModuleType('reviewed_rootfs_compare_v2')
    exec(compile(source,'<pinned-comparison-packet>','exec'),module.__dict__)
    changes={
        'cache-init.sh':[('ro,noload,nodax','ro,noload,dax=never')],
        'host_compare.py':[('jwk-rootfs-cache-compare-node-a-v1.service','jwk-rootfs-cache-compare-node-a-v2.service'),
                           ('jwk-rootfs-cache-compare-node-b-v1.service','jwk-rootfs-cache-compare-node-b-v2.service')],
        'cgroup_memory.py':[(r'node-[ab]-v1\.service',r'node-[ab]-v2\.service')],
    }
    for name,edits in changes.items():
        item=module.PAYLOAD[name];data=base64.b64decode(item['base64'],validate=True)
        need(hashlib.sha256(data).hexdigest()==item['sha256'],'Pinned embedded input differs')
        text=data.decode()
        for old,new in edits:
            need(text.count(old)==1,'Expected exact single edit: '+name)
            text=text.replace(old,new)
        data=text.encode()
        module.PAYLOAD[name]={'base64':base64.b64encode(data).decode(),'sha256':hashlib.sha256(data).hexdigest()}
    return module

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run',action='store_true');args=parser.parse_args()
    if not args.run:
        print(json.dumps({'status':'PLAN_ONLY','change':'block ext4 ro,noload,dax=never; DAX=false statx checks retained',
            'newStage':str(ROOT/'r/pm-a-v1/cache-compare-v2'),'SDK_called':False,'oldEvidenceModified':False},indent=2))
        return 0
    need(sys.platform=='linux' and os.uname().nodename=='server1' and os.uname().machine=='aarch64','Use A ARM64')
    need(os.getuid()==os.geteuid()==1204 and os.getgid()==os.getegid()==1205,'Use ordinary jwk')
    validate_prior(json.loads(read(OLD/'results/return.json',2*1024**2)))
    need(hashlib.sha256(read(OLD/'compare.json',32768)).hexdigest()==OLD_CONFIG_SHA,'Prior comparison config changed')
    module=prepare_module(read(ROOT/'rootfs_cache_compare.py',4*1024**2))
    sys.argv=['rootfs_compare_v2','--node','node-a','--dax-pass-report',str(ROOT/'r/pm-a-v1/guest-futex-v5/return.json'),
              '--guest-config',str(ROOT/'r/pm-a-v1/native-session/futex-v5/guest-config.json'),'--run']
    return module.main()

if __name__=='__main__':raise SystemExit(main())
