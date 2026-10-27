import ast,base64,hashlib,json,zlib
from pathlib import Path
HERE=Path(__file__).parent
def change(s,a,b):
    assert s.count(a)==1,(a,s.count(a));return s.replace(a,b)
def unpack(file,key):
    s=(HERE/file).read_text();tree=ast.parse(s)
    return ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign) and n.targets[0].id==key)),s.split('\n',1)[1]
def encode(raw,filename=None):
    if isinstance(raw,str):raw=raw.encode()
    ast.parse(raw,feature_version=(3,11))
    d={'sha256':hashlib.sha256(raw).hexdigest(),'z64':base64.b64encode(zlib.compress(raw,9)).decode()}
    d.update({'filename':filename} if filename else {'bytes':len(raw)});return d
helper=(HERE/'prepare_original_measurement_template_v2.py').read_text()
helper=change(helper,"    for p in (src,repo,repo/'catalog/records',repo/'managed-layers',repo/'snapshots'):",
                    "    for p in (src,src/'catalog/records',src/'managed-layers',src/'snapshots',repo,repo/'catalog/records'):")
helper=change(helper,"    receipt_dir=root/'r'/('original-template-measurement-'+node+'-v1')",'''    target_directories=[repo/'managed-layers',repo/'snapshots',repo/'snapshots'/sid]
    for p in target_directories:
        if p.exists() or p.is_symlink():
            prep_need(p.resolve(strict=True)==p and p.is_dir() and p.stat().st_uid==1204 and not p.stat().st_mode&0o022,
                      'Existing repository directory differs: '+str(p))
    receipt_dir=root/'r'/('original-template-measurement-'+node+'-v1')''')
helper=change(helper,"'missingFiles':missing,'validated':validated,'originalRuntime':context,'createdNs':time.time_ns(),",
 "'missingFiles':missing,'directoriesToCreate':[str(p) for p in target_directories if not p.exists()],'validated':validated,'originalRuntime':context,'createdNs':time.time_ns(),")
helper=change(helper,"""            snapshot_dir=repo/'snapshots'/sid
            if not snapshot_dir.exists():snapshot_dir.mkdir(mode=0o700);os.chown(snapshot_dir,1204,1205)
            prep_need(snapshot_dir.resolve(strict=True)==snapshot_dir and snapshot_dir.stat().st_uid==1204,'Snapshot directory differs')""",
"""            for p in target_directories:
                guard()
                if not p.exists():p.mkdir(mode=0o700);os.chown(p,1204,1205)
                prep_need(p.resolve(strict=True)==p and p.is_dir() and p.stat().st_uid==1204 and not p.stat().st_mode&0o022,
                          'Repository directory changed: '+str(p))""")
(HERE/'prepare_original_measurement_template_v3.py').write_text(helper,encoding='utf-8',newline='\n')

modules,body=unpack('AB_deletefix_local_comparison_v2.py','MODULES')
body=change(body,"context['fcWorkDir']=config['firecracker']['work_dir']",
"context['fcWorkDir']=config['firecracker'].get('work_dir') or str(Path(config['home_path'])/'firecracker-work')")
body=change(body,"need(work.is_relative_to(ROOT) and work.resolve(strict=True)==work,'FC working directory outside admitted deployment')",
"""need(work.is_absolute() and work.is_relative_to(ROOT) and work.resolve()==work,'FC working directory outside admitted deployment')
            # The genuine original creates its default work directory on the
            # first Guest. Its existing parent must be canonical; do not
            # require the not-yet-used directory to exist before restore.
            need(work.parent.resolve(strict=True)==work.parent and work.parent.is_dir(),'FC work parent missing or redirected')
            if work.exists():need(work.is_dir() and work.stat().st_uid==1204,'FC work directory metadata differs')
            declared=env.get(b'AENV_FIRECRACKER_WORK_DIR')
            need(declared is None or declared.decode()==str(work),'FC work environment override differs')""")
cohort=zlib.decompress(base64.b64decode(modules['cohort']['z64'])).decode()
helper_fc='''
def fc_sandbox_identity(cwd,pid):
    """Read only the instance ID from the exact FC process's Unix API."""
    import socket,http.client
    path=cwd/'firecracker.socket'
    need(path.resolve(strict=True)==path,'FC socket redirected')
    meta=path.stat();need(stat.S_ISSOCK(meta.st_mode) and meta.st_uid==1204,'FC socket ownership differs')
    client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    connection=http.client.HTTPConnection('localhost',timeout=10)
    try:
        client.settimeout(10);client.connect(str(path))
        peer_pid,peer_uid,_=struct.unpack('3i',client.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        need(peer_pid==pid and peer_uid==1204,'FC API peer process differs')
        connection.sock=client;connection.request('GET','/mmds')
        response=connection.getresponse();raw=response.read(65537)
        need(response.status==200 and len(raw)<=65536,'FC instance metadata unavailable')
        value=json.loads(raw);sid=value.get('instanceID')
        need(isinstance(sid,str) and re.fullmatch('[0-9a-f-]{36}',sid),'Invalid FC instance identity')
        return sid
    finally:connection.close();client.close()

'''
cohort=change(cohort,'class ActualComparisonCohort:',helper_fc+'class ActualComparisonCohort:')
old="""            proc=Path('/proc')/str(fc['pid']);stderr=Path(os.readlink(proc/'fd/2'))
            if stderr.name!='firecracker-stderr.log' or stderr.parent.parent!=self.base/'logs/firecracker':continue
            sid=stderr.parent.name
            need(sid in expected and sid not in found,'Unknown/additional FC in admitted Runtime')
            need(self.owned(sid) is not None,'Owned Guest disappeared')
            cwd=(proc/'cwd').resolve(strict=True)"""
new="""            proc=Path('/proc')/str(fc['pid']);cwd=(proc/'cwd').resolve(strict=True)
            known=[sid for sid,row in self.bindings.items() if row['fcIdentity']==fc and row['cwd']==str(cwd)]
            need(len(known)<=1,'FC bound to multiple Guests')
            # Logging is optional in the genuine original. Never infer the
            # Guest ID from a new deployment's stderr directory convention.
            sid=known[0] if known else fc_sandbox_identity(cwd,fc['pid'])
            need(sid in expected and sid not in found,'Unknown/additional FC in admitted Runtime')
            need(self.owned(sid) is not None,'Owned Guest disappeared')"""
cohort=change(cohort,old,new)
modules['cohort']=encode(cohort)
(HERE/'layoutfix_cohort.py').write_text(cohort,encoding='utf-8',newline='\n')
(HERE/'layoutfix_comparison_body.py').write_text(body,encoding='utf-8',newline='\n')
controller=('MODULES='+repr(modules)+'\n'+body).encode();(HERE/'AB_deletefix_local_comparison_v3.py').write_bytes(controller)
agg_modules,agg=unpack('aggregate_deletefix_comparison_v2.py','MODULES')
agg=change(agg,hashlib.sha256((HERE/'AB_deletefix_local_comparison_v2.py').read_bytes()).hexdigest(),hashlib.sha256(controller).hexdigest())
aggregate=('MODULES='+repr(agg_modules)+'\n'+agg).encode();(HERE/'aggregate_deletefix_comparison_v3.py').write_bytes(aggregate)
(HERE/'layoutfix_aggregation_body.py').write_text(agg,encoding='utf-8',newline='\n')
components,pipeline=unpack('AB_deletefix_measurement_pipeline_v2.py','COMPONENTS')
components['comparison']=encode(controller,'AB_deletefix_local_comparison_v3.py');components['aggregate']=encode(aggregate,'aggregate_deletefix_comparison_v3.py')
pipeline=pipeline.replace('AB_deletefix_measurement_pipeline_v2.py','AB_deletefix_measurement_pipeline_v3.py').replace('next-resourcefix-','next-layoutfix-')
raw=('COMPONENTS='+repr(components)+'\n'+pipeline).encode();(HERE/'AB_deletefix_measurement_pipeline_v3.py').write_bytes(raw)
for item in (controller,aggregate,raw):ast.parse(item,feature_version=(3,11))
record={'pipelineSha256':hashlib.sha256(raw).hexdigest(),'pipelineBytes':len(raw),'controllerSha256':hashlib.sha256(controller).hexdigest(),
 'aggregateSha256':hashlib.sha256(aggregate).hexdigest(),'existingMeasurementResults':False,'guestTimeout':300,'cliTimeout':330,
 'scope':'initialize missing repository dirs; honor genuine original FC work default; bind FC via exact Unix peer + MMDS instanceID; sampler/replay unchanged'}
(HERE/'baseline-layout-fix-packet.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))
