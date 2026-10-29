"""Read-only SDK/package and current-kernel build metadata; no SDK calls."""
import hashlib,json,platform,stat,subprocess
from pathlib import Path
def query(args,limit=8192):
    exe = next((str(Path(p)/args[0]) for p in ('/usr/bin','/usr/sbin','/bin','/sbin')
                if (Path(p)/args[0]).is_file()),None)
    if not exe: return {'missing':args[0]}
    try:
        r = subprocess.run([exe]+args[1:],stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=10)
        return {'rc':r.returncode,'out':r.stdout[:limit],'err':r.stderr[:1024],
                'truncated':len(r.stdout)>limit}
    except (OSError,subprocess.TimeoutExpired) as e:
        return {'unavailable':type(e).__name__}

def source_details():
    result = {'SDKCalled':False,'kernelBuild':{},'sdkLibraries':[]}
    for kind in ('build','source'):
        link = Path('/lib/modules')/platform.release()/kind
        item = {'link':str(link),'exists':link.exists(),'resolved':str(link.resolve())}
        item['requiredFiles'] = {name:(link/name).is_file() for name in
                                 ('.config','Module.symvers','include/generated/utsrelease.h',
                                  'drivers/ub/obmm/obmm_core.c','drivers/ub/obmm/obmm_shm_dev.c')}
        result['kernelBuild'][kind] = item
    for p in (Path('/usr/lib64/libubsm_sdk.so'),Path('/usr/local/lib64/libubsm_sdk.so')):
        if not p.is_file(): continue
        real=p.resolve(); info=real.stat()
        entry={'path':str(p),'real':str(real),'bytes':info.st_size,
               'uid':info.st_uid,'gid':info.st_gid,'mode':oct(stat.S_IMODE(info.st_mode))}
        if stat.S_ISREG(info.st_mode) and info.st_size<=32*1024**2:
            entry['sha256']=hashlib.sha256(real.read_bytes()).hexdigest()
        entry['package']=query(['rpm','-qf',str(real)])
        result['sdkLibraries'].append(entry)
    result['ublkModule']=query(['modinfo','ublk_drv'])
    installed=query(['rpm','-qa','--qf','%{NAME} %{VERSION}-%{RELEASE}.%{ARCH}\n'],1024**2)
    # Filter before returning; a package-name query for ubs-mem alone was incomplete.
    if installed.get('rc')==0:
        installed['out']='\n'.join(line for line in installed['out'].splitlines()
                                  if line.startswith(('ubs-','obmm ','libobmm ')))
    result['ubPackages']=installed
    return result

if __name__=='__main__':
    print('BEGIN_CD_DEPENDENCIES')
    result=source_details()
    result.update(status='CD_DEPENDENCIES_INSPECTED_NO_ACTION',hostname=platform.node(),kernel=platform.release(),servicesChanged=False,moduleChanged=False)
    print(json.dumps(result,indent=2))
    print('END_CD_DEPENDENCIES')
