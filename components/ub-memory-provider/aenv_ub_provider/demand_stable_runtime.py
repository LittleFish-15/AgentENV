"""Production stable-image role assembly, invoked by the existing runtime CLI.

This module does not install services, switch modules or generate credentials.
All native actions require a private, explicitly pinned deployment configuration.
"""
import hashlib
import json
import os
from pathlib import Path
import socket
import threading

from .host_dax_demand import Manifest, require
from .demand_wire import DEVICE_BYTES, LOAD_BYTES


def validate(config):
    require(config.get('version')==2 and config.get('mode')=='host-dax-stable-demand', 'Stable runtime v2 required')
    required=('role','run','node','ownerNode','nodes','uid','gid','hostname','machineId','bootId','kernelRelease',
              'stateRoot','sdkSocket','rootSocket',
              'sdkUnit','rootUnit','adapter','adapterSha256','region','poolBytes','logicalBudgetBytes',
              'coverageLimitBytes','imageKey','manifestPath','manifestSha256','imageSha256','indexPath')
    require(all(k in config for k in required),'Incomplete stable role configuration')
    require(config['role'] in ('owner','node','root') and config['node'] in config['nodes']
            and len(config['nodes'])==2 and len(set(config['nodes']))==2
            and config['ownerNode'] in config['nodes'],'Explicit two-node identity required')
    require(len(config['run'])==32 and all(c in '0123456789abcdef' for c in config['run']), 'Invalid run epoch')
    require(type(config['uid']) is int and config['uid']>0 and type(config['gid']) is int and config['gid']>0,
            'Explicit ordinary SDK identity required')
    require(config['poolBytes']==128*1024**2 and type(config['logicalBudgetBytes'])is int
            and config['poolBytes']<=config['logicalBudgetBytes']<=DEVICE_BYTES
            and type(config['coverageLimitBytes'])is int
            and config['coverageLimitBytes']>=config['logicalBudgetBytes'],
            'Explicit arena logical budget and post-map coverage guard required; neither is a physical quota')
    for name in ('stateRoot','sdkSocket','rootSocket','adapter','imageKey','manifestPath','indexPath'):
        require(isinstance(config[name],str) and Path(config[name]).is_absolute(),'Absolute path required: '+name)
    for name in ('sdkSocket','rootSocket'):
        require(len(os.fsencode(config[name]))<108,'UNIX socket path too long: '+name)
    for name in ('sdkUnit','rootUnit'):
        require(config[name].endswith('.service') and '/' not in config[name],'Invalid service identity')
    path=Path(config['manifestPath']);info=path.stat()
    require(path.resolve()==path and info.st_size<=4*1024**2 and not info.st_mode&0o077
            and info.st_uid==os.geteuid(),'Private owned prepared manifest required')
    prepared=json.loads(path.read_text());manifest=Manifest(prepared['document'],config['manifestSha256'])
    require(prepared['sha256']==manifest.sha256 and manifest.layer_digest==config['imageSha256']
            and manifest.chunk_bytes==LOAD_BYTES and manifest.file_bytes<=DEVICE_BYTES
            and prepared['logicalBytes']==DEVICE_BYTES,'Native image manifest differs')
    if config['role']=='owner':
        require(config['node']==config['ownerNode'] and all(k in config for k in
                ('receiptKeys','serverTls','listenHost','listenPort','nodeFingerprints','tls')), 'Owner assembly missing')
        require(set(config['receiptKeys'])==set(config['nodes'])
                and set(config['nodeFingerprints'].values())==set(config['nodes']),'Both node trust bindings required')
    elif config['role']=='node':require(config['node']!=config['ownerNode'],'Owner must use owner SDK role')
    else:
        require(all(k in config for k in ('kernelRelease','moduleSrcversion','bootId','receiptKey',
                    'tls','files','brokerSocket','ordinaryPackagePath')),'Root assembly missing')
        require(Path(config['stateRoot']).is_relative_to(Path('/home/jwk/root'))
                and Path(config['rootSocket']).is_relative_to(Path('/home/jwk/root')),
                'Root state and socket must remain under /home/jwk/root')
        require(0<len(config['files'])<=64,'Bounded template lower list required')
        from .stored import Replica
        digests=set();names=set()
        for item in config['files']:
            require(set(item)=={'name','replica'} and item['name'] not in ('','.','..')
                    and not any(c in item['name'] for c in '/\\\0'),'Direct lower filename required')
            replica=Replica(**item['replica']).validate()
            require(replica.generation==config['run'] and replica.brokerSocket==config['brokerSocket']
                    and not replica.allowRepositoryFallback and replica.layerDigest not in digests
                    and item['name'] not in names,'Duplicate or foreign lower identity')
            digests.add(replica.layerDigest);names.add(item['name'])
        if config['node']==config['ownerNode']:
            source=Path(config['sourceImage'])
            require(source.is_absolute() and source.resolve()==source and source.is_file()
                    and source.stat().st_size==manifest.file_bytes
                    and not source.is_relative_to(Path(config['stateRoot'])),'Independent immutable source image required')
    return manifest


def run(args,config):
    from .demand_runtime import key_file,client
    manifest=validate(config)
    if args.action=='validate':
        print(json.dumps({'state':'STABLE_CONFIG_VALIDATED_NO_SDK','units':len(manifest.chunks),
                          'logicalBytes':DEVICE_BYTES,'loadBytes':LOAD_BYTES,'SDK_called':False}));return
    require(os.name=='posix' and hasattr(socket,'SO_PEERCRED'),'Native Linux required')
    require((os.getuid()==os.geteuid()==0)==(config['role']=='root'),'Wrong role privilege')
    require(os.uname().machine=='aarch64' and os.uname().nodename==config['hostname']
            and os.uname().release==config['kernelRelease']
            and Path('/etc/machine-id').read_text().strip()==config['machineId']
            and Path('/proc/sys/kernel/random/boot_id').read_text().strip()==config['bootId'],
            'Role configuration belongs to another machine, boot or kernel')
    if config['role']!='root':
        require(os.getuid()==os.geteuid()==config['uid'] and os.getgid()==config['gid'],'Ordinary identity differs')
        status=Path('/proc/self/status').read_text()
        for name in ('CapInh','CapPrm','CapEff','CapAmb'):
            require(int(next(line.split()[1] for line in status.splitlines() if line.startswith(name+':')),16)==0,
                    'Ordinary SDK roles must have zero capabilities')
    if args.action!='serve':
        if args.action in ('status','drain','abort','release-root') and config['role']=='root':
            from .demand_views import RootClient
            params={}
            if args.action=='release-root':
                require(args.receipt is not None,'Explicit global release receipt required')
                params={'receipt':json.loads(Path(args.receipt).read_text())}
            result=RootClient(config['rootSocket'],config['run']).call(
                'release-control' if args.action=='release-root' else args.action,params)
        else:
            import uuid
            require(args.action in ('status','close-admission','finish'),'Unsupported stable admin action')
            result=client(config).call(args.action,uuid.uuid4().hex)
        print(json.dumps(result));return
    key=key_file(config['imageKey'])
    if config['role'] in ('owner','node'):
        from .demand_arena import ArenaSdk,ArenaDirectory
        sdk=ArenaSdk(config,key)
        if config['role']=='owner':
            from .demand_control import server
            directory=ArenaDirectory(config,manifest,sdk,key,{n:key_file(p) for n,p in config['receiptKeys'].items()})
            thread=threading.Thread(target=sdk.serve,daemon=True);thread.start()
            require(sdk.socket_ready.wait(5) and thread.is_alive(),'SDK local socket failed before admission')
            tls=config['serverTls']
            server((config['listenHost'],config['listenPort']),directory,tls['ca'],tls['certificate'],
                   tls['key'],config['nodeFingerprints']).serve_forever()
        else:sdk.serve()
    else:
        from .demand_stable import StableRoot
        root=StableRoot(config,manifest,client(config),key,key_file(config['receiptKey']))
        thread=threading.Thread(target=root.serve,daemon=True);thread.start()
        try:
            require(root.socket_ready.wait(5) and thread.is_alive(),'Root socket failed before admission')
            print(json.dumps(root.start()),flush=True)
        except Exception as error:
            with root.lock:
                root.record.update(phase='STOPPED_PRESERVE',fatal=str(error))
                try:root.save()
                except Exception:pass
            try:
                import uuid
                root.coordinator.call('halt',uuid.uuid4().hex)
            except Exception:pass
            print(json.dumps({'state':'STOPPED_PRESERVE','reason':str(error),'rootState':str(root.work/'root.json')}),flush=True)
        thread.join()  # Keep ownership/control alive for explicit inspection and retirement.
