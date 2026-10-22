"""Build a thin public packet: input hashes + two budget deltas + controllers."""
import ast,base64,hashlib,importlib.util,io,json,tarfile,zlib
from pathlib import Path
HERE=Path(__file__).resolve().parent;RELAY=HERE.parent


def compiler_inputs():
    spec=importlib.util.spec_from_file_location('previous_budget_packet',RELAY/'cow4_access_build.py')
    old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
    assert old.PATCH_SHA=='c553d631d18a01ce5511dec12e50a1a58817c92181d20f1443f17561f87a67ce'
    raw=zlib.decompress(base64.b64decode(old.BASE_ARCHIVE['base64']))
    assert hashlib.sha256(raw).hexdigest()==old.BASE_ARCHIVE['sha256']
    files={};modes={}
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as t:
        for item in t:
            if item.isfile():files[item.name]=t.extractfile(item).read();modes[item.name]=bool(item.mode&0o111)
            elif item.issym():assert item.name=='AGENTS.md' and item.linkname=='CLAUDE.md'
            else:assert item.isdir()
    for name,item in old.PATCH_FILES.items():
        files[name]=base64.b64decode(item['base64']);modes.setdefault(name,False)
        assert hashlib.sha256(files[name]).hexdigest()==item['after_sha256']
    manifest={n:{'sha256':hashlib.sha256(raw).hexdigest(),'executable':modes[n]} for n,raw in files.items()}
    changes={}
    for name,before,after in [
        ('storage/overlaybd/src/rootfs_access_trace.rs',b'1048576..=268435456',b'1048576..=536870912'),
        ('storage/overlaybd/examples/rootfs_access_calibration.rs',b'max_bytes=1048576',b'max_bytes=536870912')]:
        data=files[name];assert data.count(before)==1;changed=data.replace(before,after)
        changes[name]={'sha256':hashlib.sha256(changed).hexdigest(),'base64':base64.b64encode(changed).decode()}
    identity={'parent_observer_patch_sha256':old.PATCH_SHA,'expected_input_manifest':manifest,
              'changed_source_sha256':{n:v['sha256'] for n,v in changes.items()},'max_bytes':536870912,'max_records':1000000}
    fingerprint=hashlib.sha256(json.dumps(identity,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return manifest,changes,fingerprint,files


def core_source():
    text=(HERE/'four_run.py').read_text(encoding='utf-8');tree=ast.parse(text)
    wanted={'digest','replace_daemon','compact_ranges','inventory','summarize','FourRun'}
    pieces=[]
    for n in tree.body:
        if isinstance(n,(ast.Import,ast.ImportFrom,ast.Assign)) or isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in wanted:
            pieces.append(ast.get_source_segment(text,n))
    code='\n\n'.join(pieces)+'\n'
    assert 'range(0,8,2)' not in code and 'max_workers=8' not in code
    return code.replace('cow4-attributed-lower-cache-v1','cow17-attributed-lower-cache-v1')


def root_source(fingerprint):
    code=(HERE/'root_session.py').read_text(encoding='utf-8')
    replacements={
        "len(jobs)==8 and len({j['sandbox_id'] for j in jobs})==8":"len(jobs)==34 and len({j['sandbox_id'] for j in jobs})==34",
        "Expected eight unique Guests":"Expected 34 unique Guests",
        "len(pids)==8":"len(pids)==34",
        "endpoint.name=='c4-'":"endpoint.name=='c17-'",
        "require(hashlib.sha256(scoped_read(candidate,128*1024**2)).hexdigest()==plan['candidate_sha256']=='eed36d01de13f83a8abdc13e93c21883a3a48273da83fa1c813e65e4655babcf','Candidate differs')":
            "candidate_bytes=scoped_read(candidate,128*1024**2)\n        require(hashlib.sha256(candidate_bytes).hexdigest()==plan['candidate_sha256'],'Candidate differs')\n        require("+repr(fingerprint)+".encode() in candidate_bytes,'Candidate budget fingerprint differs')"}
    for old,new in replacements.items():
        assert code.count(old)==1,old
        code=code.replace(old,new)
    code=code.replace('COW4_','COW17_').replace('cow4-restore-','cow17-restore-')
    progress={
        "        before=unit_state();assert_unit(before)":"        print('ROOT_PHASE=preflight',flush=True)\n        before=unit_state();assert_unit(before)",
        "        wire_send(sock,{'op':'ready'})":"        print('ROOT_PHASE=waiting_owner_activation',flush=True)\n        wire_send(sock,{'op':'ready'})",
        "        # Only this existing original unit is restarted, never stopped/unloaded.":"        print('ROOT_PHASE=activate_original_service',flush=True)\n        # Only this existing original unit is restarted, never stopped/unloaded.",
        "        until=time.monotonic()+5400":"        print('ROOT_PHASE=waiting_guest_binding',flush=True)\n        until=time.monotonic()+5400;last_progress=time.monotonic()",
        "            request=wire_recv(sock);op=request.get('op')":"            request=wire_recv(sock);op=request.get('op')\n            if time.monotonic()-last_progress>=60:\n                print('ROOT_HEARTBEAT=supervising_original_service',flush=True);last_progress=time.monotonic()",
        "            if op=='bind':":"            if op=='bind':\n                print('ROOT_PHASE=bind_34_guests',flush=True)",
        "                report['observer_identity']=[pid,ticks]":"                report['observer_identity']=[pid,ticks]\n                print('ROOT_PHASE=collecting',flush=True)",
        "                # Recovery is limited to exact original bytes and an empty service.":"                print('ROOT_PHASE=checking_restore',flush=True)\n                # Recovery is limited to exact original bytes and an empty service."}
    for old,new in progress.items():
        assert code.count(old)==1,old
        code=code.replace(old,new)
    anchor="    require({j['template_id'] for j in jobs}==set(plan['template_lowers']),'Template scope differs')"
    assert code.count(anchor)==1
    code=code.replace(anchor,anchor+"\n    require(len(plan['template_lowers'])==17 and all(sum(j['template_id']==t for j in jobs)==2 for t in plan['template_lowers']),'Expected 17 pairs')")
    return code


def build():
    inputs,deltas,fingerprint,_=compiler_inputs()
    payload={}
    sources={'engine':(RELAY/'cow55_replay.py').read_text(encoding='utf-8'),
        'accounting':(HERE/'page_accounting.py').read_text(encoding='utf-8'),
        'process':(RELAY/'cow55_process_summary.py').read_text(encoding='utf-8'),
        'details':(RELAY/'cow_rootfs_details.py').read_text(encoding='utf-8'),
        'core':core_source(),'root':root_source(fingerprint),'builder':(HERE/'seventeen_build.py').read_text(encoding='utf-8')}
    for name,text in sources.items():
        raw=text.encode();compile(text,'embedded-'+name,'exec')
        payload[name]={'sha256':hashlib.sha256(raw).hexdigest(),'base64':base64.b64encode(raw).decode()}
    prefix='''"""Single-file original 17-template access experiment; no private workload payload."""
import base64,hashlib,sys,types
'''+ 'EMBEDDED='+repr(payload)+'\nINPUTS='+repr(inputs)+'\nDELTAS='+repr(deltas)+'\nBUDGET_PATCH_SHA='+repr(fingerprint)+'''
def _source(name):
    item=EMBEDDED[name];raw=base64.b64decode(item['base64'],validate=True)
    if hashlib.sha256(raw).hexdigest()!=item['sha256']:raise RuntimeError('Embedded source differs')
    return raw.decode()
def _module(name,bindings=None):
    m=types.ModuleType('cow17_'+name);m.__file__=__file__+'#'+name
    m.__dict__.update(bindings or {});sys.modules[m.__name__]=m
    exec(compile(_source(name),m.__file__,'exec'),m.__dict__);return m
ENGINE=_module('engine')
ACCOUNTING=_module('accounting')
PROCESS=_module('process')
DETAILS=_module('details')
CORE=_module('core',{'ENGINE':ENGINE,'ACCOUNTING':ACCOUNTING,'PROCESS':PROCESS,'DETAILS':DETAILS})
BUILD=_module('builder',{'INPUTS':INPUTS,'DELTAS':DELTAS,'PATCH_SHA':BUDGET_PATCH_SHA,'ACCOUNTING':ACCOUNTING})
ROOT_SOURCE=_source('root')
'''
    footer='''
if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print('BEGIN_RETURN_REPORT')
        print(json.dumps({'status':'STOPPED_COW17_ACCESS_ENTRY','error_type':type(error).__name__,'reason':str(error)},indent=2))
        print('END_RETURN_REPORT')
        raise SystemExit(1)
'''
    raw=(prefix+(HERE/'seventeen_run.py').read_text(encoding='utf-8')+footer).encode()
    compile(raw,'cow17-access-once','exec');(RELAY/'cow17_access_once.py').write_bytes(raw)
    return {'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'patch_sha256':fingerprint,'source_files':len(inputs),'changed_compiler_sources':list(deltas)}


if __name__=='__main__':print(json.dumps(build(),indent=2))
