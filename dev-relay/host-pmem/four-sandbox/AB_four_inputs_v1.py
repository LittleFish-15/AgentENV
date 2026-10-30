"""Bounded ordinary-user experiment admission; no Guest, SDK or service actions."""
import base64,hashlib,json,os,platform,stat
from pathlib import Path
ROOT=Path('/home/jwk/agent')
TEMPLATE='01a15c9e-54d0-7b92-a50b-0b6ec2e9136b'
def need(ok,reason):
    if not ok:raise RuntimeError(reason)
def info(path,hash_content=False):
    p=Path(path)
    try:
        need(p.resolve(strict=True)==p,'Redirected input')
        s=p.stat();need(stat.S_ISREG(s.st_mode) and s.st_size<=128*1024**2,'Input type/size differs')
        r={'path':str(p),'bytes':s.st_size,'uid':s.st_uid,'gid':s.st_gid,'mode':oct(stat.S_IMODE(s.st_mode)),'sha256':None}
        if hash_content:
            h=hashlib.sha256()
            with p.open('rb') as f:
                for data in iter(lambda:f.read(1024**2),b''):h.update(data)
            t=p.stat();need((s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(t.st_ino,t.st_size,t.st_mtime_ns,t.st_ctime_ns),'Changed input')
            r['sha256']=h.hexdigest()
        return r
    except (OSError,RuntimeError) as e:return {'path':str(p),'unavailable':type(e).__name__}
def main():
    need(os.getuid()==os.geteuid()==1204 and os.getgid()==1205,'Use ordinary jwk')
    spec=json.loads(Path('task-input.json').read_bytes())
    actual={'hostname':platform.node(),'uid':os.getuid(),'gid':os.getgid(),'architecture':platform.machine(),
            'kernel':platform.release(),'machineId':Path('/etc/machine-id').read_text().strip(),
            'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    need(actual==spec['expectedIdentity'],'Boot differs')
    n={'server1':'a','agent1':'b'}[platform.node()]
    manifest=ROOT/'r/lazy-four-rollout-v1/snapshots/manifest.json'
    selection=manifest.parent/'selection.private.json'
    mi=info(manifest,True);si=info(selection,True)
    need(mi.get('sha256') and si.get('sha256'),'Retained workload unavailable')
    meta=json.loads(manifest.read_bytes())
    need(meta['files']['selection.private.json']['sha256']==si['sha256'],'Workload manifest mismatch')
    selected=json.loads(selection.read_bytes())['selected']
    case=next(x for x in selected if x['original']['template_id']==TEMPLATE)
    replay=base64.b64decode(case['replayBase64'],validate=True)
    need(hashlib.sha256(replay).hexdigest()=='98bf22ac009171ca086cdaf0af6d1924b7823b48cbbd10febe8c969a124d63ab','Replay differs')
    baseline=ROOT/'deployments/agentenv-ae9c626-baseline'
    files=[info(baseline/r,True) for r in ('bin/server','bin/aenv','bin/uvm-ublk-daemon',
        'deps/firecracker/1.15.1-patch-v3/firecracker')]
    observer=ROOT/'relay/reports/node-a-rootfs-access-build-abcks95d/candidate/uvm-ublk-daemon-observe' if n=='a' else ROOT/'r/hpd4-b-v1/uvm-ublk-daemon-original-observer'
    files.append(info(observer,True))
    rules=[]
    for directory in ('/etc/udev/rules.d','/run/udev/rules.d','/usr/lib/udev/rules.d'):
        for p in sorted(Path(directory).glob('*ublk*.rules'))[:16]:
            row=info(p,True)
            if row.get('bytes',99999)<=16384:
                try:row['rules']=p.read_text()
                except OSError:pass
            rules.append(row)
    report={'status':'FOUR_SANDBOX_INPUTS_INSPECTED_NOT_EXECUTED','identity':actual,'templateId':TEMPLATE,
        'replaySha256':hashlib.sha256(replay).hexdigest(),'executedStepCount':case['executedStepCount'],
        'selection':si,'manifest':mi,'baselineArtifacts':files,'ublkRules':rules,
        'SDK_called':False,'Guest_created':False,'servicesChanged':False,'privateWorkloadContentsPrinted':False}
    print(json.dumps(report,indent=2))
if __name__=='__main__':main()
