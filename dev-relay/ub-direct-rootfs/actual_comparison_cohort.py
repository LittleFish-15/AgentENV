"""Native cohort adapter for already-admitted original/full local Runtimes.

Uses the existing durable Cohort API engine and pinned proc/FC observers. It
does not allocate UB, provision communication, copy layers or modify services.
The caller must supply validated inputs and pass the cross-node acceptance,
budget and synchronization gates before calling restore or release.
"""
import hashlib,json,os,re,stat,struct,time
from pathlib import Path

def need(ok,why):
    if not ok:raise RuntimeError(why)

def content_signature(layers):
    return hashlib.sha256(json.dumps([(r['digest'],r['size']) for r in layers],separators=(',',':')).encode()).hexdigest()

def check_binding(config,expected,variant,index):
    need(variant in ('original','full') and len(config['lowers'])==len(expected)>0,'Rootfs scope differs')
    refs={} if variant=='original' else {r['layerDigest']:r for r in index['replicas']}
    if variant=='full':need(index['version']==1 and index['state']=='ready' and len(refs)==len(index['replicas']), 'Invalid/duplicate full index')
    for actual,wanted in zip(config['lowers'],expected):
        need(actual['digest']==wanted['digest'] and actual['size']==wanted['size'],'Actual lower content/order differs')
        if variant=='original':need(actual.get('ub') is None,'Original Guest unexpectedly uses UB')
        else:
            reference=refs.get(wanted['digest'])
            need(reference is not None and reference['allowRepositoryFallback'] is False and actual.get('ub')==reference,
                 'Required UB binding differs or permits fallback')

class ActualComparisonCohort:
    def __init__(self,api,engine,readiness,ram_observer,sampler,base,variant,templates,context,persist,capacity,index=None):
        need(variant in ('original','full') and len(templates) in (1,4),'Explicit original/full one/four template scope required')
        need([r['templateIndex'] for r in templates]==list(range(len(templates))),'Template ordering differs')
        need(all(r['resources']=={'cpu_count':2,'memory_mib':4096} for r in templates),'Fixed resources differ')
        need(variant=='original' or index is not None,'Full mode requires pinned index')
        self.api,self.engine,self.ready,self.ram,self.sampler=api,engine,readiness,ram_observer,sampler
        self.base,self.variant,self.templates,self.context=Path(base),variant,templates,context
        self.persist,self.capacity,self.index=persist,capacity,index
        self.cases={};self.jobs=[];self.bindings={};self.daemon=None
        self.root=Path('/home/jwk/agent')

    def guard(self):
        need(os.name=='posix' and os.geteuid()==0,'Root is required for actual process/device observation before mutation')
        self.api.stable()
        need(self.api.pid==self.context['pid'] and self.api.ticks==self.context['startTicks']
             and self.api.config_sha==self.context['configSha256'],'Admitted Runtime context changed')
        need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==self.context['bootId'],'Boot changed')
        need(all(not case.state['openRequests'] for case in self.cases.values()),'Unresolved mutation blocks new cohort actions')

    def writer(self,index):
        def save(state):self.persist(index,state)
        return save

    def restore(self,run_id):
        need(re.fullmatch('[0-9a-f]{32}',run_id) and not self.cases and not self.jobs,'Fresh explicit batch required')
        self.guard();need(self.api.call('GET','/v2/sandboxes?limit=1')==(200,[]),'Runtime inventory must be empty')
        self.capacity('batch',len(self.templates)*2)
        for index,template in enumerate(self.templates):
            case_id=hashlib.sha256((run_id+':'+str(index)).encode()).hexdigest()[:32]
            case=self.engine.Cohort(self.api,{'version':1,'phase':'prepared','sandboxIds':[],'openRequests':[],
                'outcomeUncertain':False,'runtimeContext':self.context},self.writer(index),None,None,
                lambda kind:self.capacity(kind,1),None,run_id=case_id,mutation_guard=self.guard)
            self.cases[index]=case
            for slot in (0,1):
                self.guard()
                sid=case.create('/v2/sandboxes',{'templateID':template['templateId'],'timeout':7200,
                    'secure':True,'autoPause':False,'allow_internet_access':False,
                    'metadata':{'cow_batch':case_id,'full_compare_batch':run_id,'variant':self.variant,
                                'template_index':str(index),'slot':str(slot)}})
                self.jobs.append({'templateId':template['templateId'],'templateIndex':index,'slot':slot,
                    'sandboxId':sid,'replaySha256':template['replaySha256'],'catalogSha256':template['catalogSha256'],
                    'resources':template['resources'],'lowerContentSha256':content_signature(template['rootfsLayers'])})
        need(len(self.jobs)==len({r['sandboxId'] for r in self.jobs})==len(self.templates)*2,'Wrong actual Guest count')
        return list(self.jobs)

    def owned(self,sid):
        cases=[case for case in self.cases.values() if sid in case.state['sandboxIds']]
        need(len(cases)==1,'Guest is not uniquely owned by this cohort')
        return cases[0].owned(sid)

    def observe(self):
        self.guard();expected={j['sandboxId']:j for j in self.jobs};found={}
        daemons=self.ready.find_processes(self.base/'bin/uvm-ublk-daemon',self.api.cgroup)
        need(len(daemons)==1,'Expected one exact daemon for active cohort')
        if self.daemon is None:self.daemon=daemons[0]
        else:need(daemons[0]==self.daemon,'Storage daemon restarted/changed during cohort')
        fcpath=self.base/'deps/firecracker/1.15.1-patch-v3/firecracker'
        for fc in self.ready.find_processes(fcpath,self.api.cgroup):
            proc=Path('/proc')/str(fc['pid']);stderr=Path(os.readlink(proc/'fd/2'))
            if stderr.name!='firecracker-stderr.log' or stderr.parent.parent!=self.base/'logs/firecracker':continue
            sid=stderr.parent.name
            need(sid in expected and sid not in found,'Unknown/additional FC in admitted Runtime')
            need(self.owned(sid) is not None,'Owned Guest disappeared')
            cwd=(proc/'cwd').resolve(strict=True)
            need(cwd.is_relative_to(self.root/'r') and cwd.name.startswith('agentenv-fc-'),'Unexpected FC working directory')
            image=cwd/'overlaybd/image.json';need(image.resolve(strict=True)==image and image.stat().st_size<=1024**2,'Unexpected image config')
            raw=image.read_bytes();config=json.loads(raw);job=expected[sid]
            layers=self.templates[job['templateIndex']]['rootfsLayers']
            check_binding(config,layers,self.variant,self.index)
            upper={}
            for kind in ('data','index'):
                path=Path(config['upper'][kind]);path=path if path.is_absolute() else image.parent/path
                need(path.resolve(strict=True)==path and path.is_relative_to(cwd),'Upper outside private Guest directory')
                meta=path.stat();need(stat.S_ISREG(meta.st_mode) and meta.st_uid==1204 and meta.st_nlink==1,'Unexpected upper type/ownership/link count')
                upper[kind]={'path':str(path),'identity':self.sampler.immutable_identity(meta),'category':'private-upper','immutable':False}
            need(len({(row['identity']['dev'],row['identity']['inode']) for row in upper.values()})==2,'Upper data/index alias')
            device=(cwd/'user-rootfs').resolve(strict=True);meta=device.stat()
            need(re.fullmatch('/dev/ublkb[0-9]+',str(device)) and stat.S_ISBLK(meta.st_mode),'Unexpected rootfs device')
            opened=False
            for fd in (proc/'fd').iterdir():
                try:
                    item=fd.stat();opened|=stat.S_ISBLK(item.st_mode) and item.st_rdev==meta.st_rdev
                except FileNotFoundError:continue
            need(opened,'FC does not hold declared rootfs device')
            queue_kib=int((Path('/sys/class/block')/device.name/'queue/max_sectors_kb').read_text())
            need(queue_kib==256,'Rootfs device is not the fixed 256KiB reference setting')
            if self.variant=='original':
                for actual,wanted in zip(config['lowers'],layers):
                    path=Path(actual['file']);path=path if path.is_absolute() else image.parent/path
                    expected_path=self.base/'state/snapshot-store/repository/managed-layers'/(wanted['digest'].replace(':','_')+'.overlaybd.commit')
                    left,right=path.stat(),expected_path.stat()
                    need((left.st_dev,left.st_ino,left.st_size)==(right.st_dev,right.st_ino,wanted['size']), 'Original backend uses different lower file')
            need(self.ready.process(fc['pid'],fcpath,self.api.cgroup)==fc,'FC identity changed')
            found[sid]={'sandboxId':sid,'fcIdentity':fc,'cwd':str(cwd),'imageConfigPath':str(image),
                        'daemonIdentity':self.daemon,
                        'imageConfigSha256':hashlib.sha256(raw).hexdigest(),'rootfsDevice':str(device),
                        'rootfsDeviceIdentity':{'major':os.major(meta.st_rdev),'minor':os.minor(meta.st_rdev),'inode':meta.st_ino},
                        'upper':upper,'upperMode':config['upper'].get('mode') or 'logStructured',
                        'rootfsMaxSectorsKiB':queue_kib,
                        'lowerContentSha256':content_signature(layers),'variant':self.variant}
        need(set(found)==set(expected),'Every actual Guest must have an observed binding')
        if self.bindings:
            for sid,value in found.items():
                old=self.bindings[sid]
                for key in ('fcIdentity','daemonIdentity','imageConfigSha256','rootfsDevice','rootfsDeviceIdentity','lowerContentSha256','rootfsMaxSectorsKiB'):
                    need(value[key]==old[key],'Guest binding changed during cohort: '+key)
        else:self.bindings=found
        self.guard();return found

    def process_scope(self,pid,ticks,role,uid=1204):
        proc=Path('/proc')/str(pid);actual=self.sampler.identity(pid)
        need(actual['startTicks']==ticks and actual['uids']==[uid]*4,'Sample process identity differs')
        executable=os.readlink(proc/'exe');meta=os.stat(proc/'exe')
        return {'pid':pid,'startTicks':ticks,'role':role,'uid':uid,'executable':executable,'exeDev':meta.st_dev,'exeInode':meta.st_ino}

    def sampling_scope(self,node,immutable_files,provider,ledger):
        expected={r['digest']:r['size'] for template in self.templates for r in template['rootfsLayers']}
        for category in ('rootfs-lower-original','rootfs-lower-ub-source'):
            selected={r.get('contentDigest'):r['identity']['size'] for r in immutable_files if r['category']==category}
            need(selected==expected,'Sampling scope omits selected ordinary lower source files: '+category)
        found=self.observe();processes=[self.process_scope(self.api.pid,self.api.ticks,'runtime')]
        processes.append(self.process_scope(self.daemon['pid'],self.daemon['startTicks'],'daemon'))
        processes.append(self.process_scope(provider['pid'],provider['startTicks'],'provider'))
        collector=self.sampler.identity(os.getpid());processes.append(self.process_scope(os.getpid(),collector['startTicks'],'collector',os.geteuid()))
        files=list(immutable_files);devices={};warnings=[]
        import fcntl
        for sid,binding in found.items():
            fc=binding['fcIdentity'];processes.append(self.process_scope(fc['pid'],fc['startTicks'],'fc'))
            files.extend(binding['upper'].values())
            names=[binding['rootfsDevice']]
            try:
                log=self.base/'logs/firecracker'/sid/'firecracker.log'
                need(log.resolve(strict=True)==log and log.stat().st_uid==1204 and log.stat().st_size<=16*1024**2,'Unexpected owned FC log')
                names.append(self.ram.memory_backend(log.read_text()))
            except (OSError,RuntimeError,ValueError) as error:
                warnings.append({'sandboxId':sid,'component':'memory-device-cache','available':False,
                                 'reason':str(error)[:200],'guestRamBytes':None})
            for name in names:
                path=Path(name);meta=path.stat();key=(os.major(meta.st_rdev),os.minor(meta.st_rdev))
                need(stat.S_ISBLK(meta.st_mode),'Expected block device')
                fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC)
                try:
                    current=os.fstat(fd);need((current.st_rdev,current.st_ino)==(meta.st_rdev,meta.st_ino),'Device reused before capacity query')
                    size=struct.unpack('=Q',fcntl.ioctl(fd,0x80081272,b'\0'*8))[0]
                finally:os.close(fd)
                devices[key]={'path':name,'major':key[0],'minor':key[1],'inode':meta.st_ino,'bytes':size}
        return {'version':1,'root':str(self.root),'node':node,'group':self.variant,'bootId':self.context['bootId'],
                'processes':processes,'files':files,'devices':list(devices.values()),'ubReservation':ledger,
                'deviceObservationWarnings':warnings}

    def collect(self,node,immutable_files,provider,ledger,*,include_files):
        scope=self.sampling_scope(node,immutable_files,provider,ledger)
        sample=self.sampler.sample(scope,include_files=include_files)
        sample['deviceObservationWarnings']=scope['deviceObservationWarnings']
        sample['actualUpperModes']={sid:value['upperMode'] for sid,value in self.bindings.items()}
        sample['rootfsMaxSectorsKiB']={sid:value['rootfsMaxSectorsKiB'] for sid,value in self.bindings.items()}
        if include_files:
            sample['authoritativeGuestRam']=self.ram.collect_ram(self.base,self.api.pid,self.api.ticks,[j['sandboxId'] for j in self.jobs])
            sample['GuestRAMAndDeviceCacheMustNotBeAdded']=True
        else:sample['authoritativeGuestRam']=None
        self.guard();return sample

    def release_after_completed_replay(self,report):
        need(report['status']=='LOCAL_REPLAY_COMPLETED_GUESTS_RETAINED' and report['pendingCommands']==0,
             'Failed/uncertain replay requires explicit reconciliation; no automatic Guest deletion')
        need({r['sandboxId'] for r in report['jobs']}=={j['sandboxId'] for j in self.jobs},'Replay/cleanup ownership differs')
        self.observe();released=[]
        for job in self.jobs:
            sid=job['sandboxId'];case=self.cases[job['templateIndex']];binding=self.bindings[sid]
            need(not case.state['openRequests'],'Unknown API operation blocks cleanup')
            case.delete(sid)
            deadline=time.monotonic()+10
            while True:
                try:alive=self.sampler.identity(binding['fcIdentity']['pid'])['startTicks']==binding['fcIdentity']['startTicks']
                except FileNotFoundError:alive=False
                # Original pooling policy is retained; only required-UB private
                # rootfs devices are required to disappear here.
                gone=self.variant=='original' or not Path(binding['rootfsDevice']).exists()
                if not alive and gone:break
                need(time.monotonic()<deadline,'Guest/device exit unconfirmed; preserve state')
                time.sleep(.2)
            released.append({'sandboxId':sid,'fcExitConfirmed':True,'requiredUBDeviceExitConfirmed':self.variant=='full',
                             'originalDevicePoolPolicyRetained':self.variant=='original'})
        need(self.api.call('GET','/v2/sandboxes?limit=1')==(200,[]),'Runtime not empty after owned cleanup')
        for case in self.cases.values():
            need(not case.state['sandboxIds'] and not case.state['openRequests'],'Lifecycle remains uncertain')
            case.state['phase']='quiesced';case.save()
        return {'ownedGuestsReleased':True,'released':released,'sharedUBObjectsRetired':False,
                'providerLeaseDrainStillRequiresVerification':self.variant=='full',
                'scope':'owned local cohort only; no cross-node or SDK object retirement'}
