"""Read-only current-state gate after external cleanup; never activates/cleans.

Reuse the already downloaded, SHA-pinned experiment's read-only checks.
No SDK initialization, ioctl, service/module operation or journal mutation.
Source hashing may warm dedicated preparation files; the experiment separately
advises those exact files away and measures remaining residency before testing.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import time
import types

ENTRY_SHA='0c28b297cfbcafb779b958c7742251b8588847ff065b1266bc2da07833b51fca'
ENTRY_BYTES=123604
ENTRIES={'server1':('node-a','/var/tmp/host-pmem-entry.XKvZys'),
         'agent1':('node-b','/var/tmp/host-pmem-entry.GpcGsh')}


def load_entry(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022
                or info.st_size!=ENTRY_BYTES):
            raise ValueError('Retained verified entry identity differs')
        data=stream.read(ENTRY_BYTES+1)
    if hashlib.sha256(data).hexdigest()!=ENTRY_SHA:
        raise ValueError('Retained entry SHA256 differs')
    module=types.ModuleType('verified_plan_components');module.__file__=str(path)
    exec(compile(data,str(path),'exec'),module.__dict__)
    return module


def inspect(module,node):
    ops=module.Operations(node,{})
    m=module.maintenance
    report={'node':node,'observedUnixNs':time.time_ns(),'entrySha256':ENTRY_SHA,
            'checks':{},'SDK_called':False,'servicesChanged':False,'moduleChanged':False,
            'cleanupExecuted':False,'maintenanceExecuted':False,'twoNodeAccepted':False,
            'netSavingsBytes':None,'scope':'current local maintenance prerequisites; not global object lifecycle acceptance'}
    def check(name,function):
        try:
            result=function()
            report['checks'][name]={'passed':True,'value':result}
            return result
        except Exception as error:
            report['checks'][name]={'passed':False,'errorType':type(error).__name__,'reason':str(error)}
            return None
    def require(value,reason):
        if not value:raise ValueError(reason)

    report['kernelRelease']=platform.release()
    check('kernel',lambda:require(report['kernelRelease']==module.KERNEL,'Kernel differs from built candidate'))
    report['bootId']=check('boot',lambda:m.read('/proc/sys/kernel/random/boot_id'))
    report['taint']=check('taint',lambda:m.read('/proc/sys/kernel/tainted'))
    def policy():
        values={'modulesDisabled':m.read('/proc/sys/kernel/modules_disabled'),
                'signatureEnforced':m.read('/sys/module/module/parameters/sig_enforce'),
                'lockdown':m.read('/sys/kernel/security/lockdown')}
        require(values['modulesDisabled']=='0' and values['signatureEnforced']=='N'
                and '[none]' in values['lockdown'],'Module policy does not permit the reviewed candidate')
        return values
    check('modulePolicy',policy)
    report['loadedSrcversion']=check('moduleIdentity',lambda:m.read('/sys/module/obmm/srcversion'))
    report['regionDevices']=check('regionInventory',lambda:sorted(p.name for p in Path('/sys/devices/obmm').glob('obmm_shmdev*')))
    report['referenceCount']=check('referenceCount',lambda:m.read('/sys/module/obmm/refcnt'))
    check('originalModuleAndNoRegions',lambda:m.check_module(m.OLD_SRC,m.PARAMS))
    check('originalInstalledBytes',lambda:require(hashlib.sha256(m.pinned_bytes(m.OLD_FILE,m.OLD_SHA)).hexdigest()==m.OLD_SHA,'Original module changed'))
    def service():
        value=m.service()
        report['ubseService']=value
        require(value['ActiveState']=='active' and int(value['MainPID'])>0,'UBSE is not active; no implicit restart')
        for key in ('RequiredBy','BoundBy','ConsistsOf','PropagatesStopTo'):
            require(not value[key],'Stopping UBSE may affect other units: '+key)
        return m.process(int(value['MainPID']))
    current=check('ubse',service)
    report['ubseProcess']=current
    if current:
        snapshot=check('referenceScan',lambda:m.reference_snapshot(current))
        if snapshot is not None:
            check('referencesAttributed',lambda:m.validate_reference_snapshot(snapshot,current['pid']))
    else:
        check('referencesAttributed',lambda:require(False,'No current UBSE identity for attribution'))
    check('retainedPreparationAndInputs',ops.validate_prepared)
    check('retainedAdapter',lambda:require(hashlib.sha256(module.read_bytes(Path(ops.plan['adapterFile']),16*module.MIB)).hexdigest()==module.ADAPTER_SHA,'Adapter changed'))
    def no_transaction():
        existing=[str(p) for p in (m.STAGE,ops.work/'workflow.json') if p.exists() or p.is_symlink()]
        require(not existing,'Existing transaction preserved: '+str(existing))
    check('unusedMaintenanceTransaction',no_transaction)
    expected=ops.plan['maintenance']
    report['bindingDifferences']={key:{'expected':expected[key],'observed':value}
        for key,value in [('bootId',report['bootId']),('taintBefore',report['taint']),('ubseProcess',current)]
        if expected[key]!=value}
    ready=all(value['passed'] for value in report['checks'].values())
    report['localPrerequisitesPassed']=ready
    report['pinnedEntryIdentityMatches']=not report['bindingDifferences']
    report['status']=('HOST_PMEM_PREMAINTENANCE_READY_FOR_PINNED_ENTRY' if ready and not report['bindingDifferences']
                      else 'HOST_PMEM_PREMAINTENANCE_REBIND_REQUIRED' if ready
                      else 'HOST_PMEM_PREMAINTENANCE_STOPPED_NO_ACTION')
    report['automaticMaintenanceAllowed']=False
    return report


def main():
    if os.getuid()!=0 or os.geteuid()!=0:raise ValueError('Expected root for read-only kernel/reference inspection')
    node,path=ENTRIES[platform.node()]
    result=inspect(load_entry(Path(path)),node)
    print('BEGIN_HOST_PMEM_PREMAINTENANCE')
    print(json.dumps(result,indent=2))
    print('END_HOST_PMEM_PREMAINTENANCE')
    return 0 if result['status']=='HOST_PMEM_PREMAINTENANCE_READY_FOR_PINNED_ENTRY' else 1


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'status':'HOST_PMEM_PREMAINTENANCE_STOPPED_NO_ACTION',
                          'errorType':type(error).__name__,'reason':str(error),'maintenanceExecuted':False}))
        raise SystemExit(1)
