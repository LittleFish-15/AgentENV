"""Make a fresh original-256 trial using the executed original global packet."""
import ast,base64,hashlib,importlib.util,json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
BASE_SHA='4dc486145378f945df9a285e9bee0fe7368c147a67699b3343ce47bc8200ceb1'


def once(s,a,b):
    assert s.count(a)==1,a
    return s.replace(a,b)


def generate(path):
    raw=path.read_bytes();assert hashlib.sha256(raw).hexdigest()==BASE_SHA
    spec=importlib.util.spec_from_file_location('original_global_256',path);old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
    text,footer=raw.decode().rsplit("if __name__=='__main__':",1)
    node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name=='main')
    before=ast.get_source_segment(text,node);main=before
    main=once(main,"m.PENDING=m.ROOT/'relay/cow4-global-cache-v2-node-a.pending.json'","m.PENDING=m.ROOT/'relay/cow4-original-256-recheck-node-a.pending.json'")
    main=once(main,'retry=BASELINE.reconcile(m,identity,api)','retry=RECHECK.reconcile(m,identity,api)')
    main=once(main,"prefix='node-a-cow4-global-'","prefix='node-a-cow4-256-recheck-'")
    main=once(main,"revision='cow4-global-cache-v2',variant='original_with_diagnostic_observer'","revision='cow4-original-256-recheck-v1',variant='original_256_recheck_with_diagnostic_observer'")
    main=once(main,'selected,built=choose(inputs,build,previous)',"selected,built=choose(inputs,build,previous)\n    m.need(sorted(b['template_id'] for b in built)==retry['baseline_template_ids'],'Template set differs from IO64 trial')")
    main=once(main,'    cohort.report.update(root_plan=plan,template_lowers=template_lowers,',"    s=(m.BASE/'bin/server').stat()\n    plan.update(original_server_sha256=RECHECK.ORIGINAL_SERVER_SHA,original_server_metadata={'dev':s.st_dev,'inode':s.st_ino,'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'bytes':s.st_size},previous_io64_run_id=RECHECK.IO64_RUN,first_256_run_id=RECHECK.FIRST_256_RUN)\n    cohort.report.update(root_plan=plan,template_lowers=template_lowers,")
    main=main.replace('COW4_GLOBAL_V2_ROOT','COW4_ORIGINAL_256_RECHECK_ROOT')
    main=once(main,"and restored.get('observer_exit_confirmed') and cohort.report['cache_crosscheck_passed']","and restored.get('observer_exit_confirmed') and restored.get('original_server_unchanged') and restored.get('rootfs256_memory256_verified') and cohort.report['cache_crosscheck_passed']")
    main=once(main,"                result['validation']={'status':", "                result['implementation']='original_256_recheck_with_diagnostic_observer'\n                result['experiment_comparison']={'first_256_run_id':RECHECK.FIRST_256_RUN,'previous_io64_run_id':RECHECK.IO64_RUN,'base_commit':'ae9c62693839ce7effa2b45df31c0039ae4f9fbc','io64_core_changes_used':False,'rootfs_max_io_kib':256,'memory_max_io_kib':256,'server_sha256':RECHECK.ORIGINAL_SERVER_SHA,'daemon_sha256':CANDIDATE_SHA,'observer_patch_sha256':PATCH_SHA,'effective_limits':restored.get('effective_device_limits'),'scope':'Byte-identical original server and original read observer; no runtime binary replacement or UB code'}\n                result['validation']={'status':")
    main=main.replace('COW4_POST_DROP_BASELINE_MEASURED_GUESTS_RELEASED_ORIGINAL_RESTORED','COW4_ORIGINAL_256_RECHECK_MEASURED_GUESTS_RELEASED_RESTORED')
    text=once(text,before,main)
    root=old.ROOT_SOURCE
    root=once(root,'        before=unit_state();assert_unit(before)',"        print('ROOT_PHASE=verify_byte_identical_original_server',flush=True)\n        before=unit_state();assert_unit(before)\n        verify_original_server(plan,before)\n        report['original_server_sha256']=ORIGINAL_SERVER_SHA\n        report['server_binary_replaced']=False")
    root=once(root,"        wire_send(sock,{'op':'ready'})","        print('ROOT_PHASE=ready_for_owner',flush=True)\n        wire_send(sock,{'op':'ready'})")
    root=once(root,'        # Only this existing original unit is restarted, never stopped/unloaded.',"        print('ROOT_PHASE=activate_original_observer_256',flush=True)\n        verify_original_server(plan,before)\n        # Only this existing original unit is restarted, never stopped/unloaded.")
    root=once(root,'        active=wait_health();assert_unit(active)','        active=wait_health();assert_unit(active)\n        verify_original_server(plan,active)')
    root=once(root,"        bound.append({'sandbox_id':b['sandbox_id']","        limits=original_bound_limits(b)\n        bound.append({'effective_device_limits':limits,'sandbox_id':b['sandbox_id']")
    root=once(root,"                report['observer_identity']=[pid,ticks]","                report['observer_identity']=[pid,ticks]\n                report['effective_device_limits']=[{'sandbox_id':b['sandbox_id'],'template_id':b['template_id'],**b['effective_device_limits']} for b in bound]\n                report['rootfs256_memory256_verified']=len(bound)==8\n                print('ROOT_PHASE=rootfs256_memory256_verified_8_of_8',flush=True)")
    root=once(root,'        until=time.monotonic()+5400',"        print('ROOT_PHASE=waiting_for_guests_and_sampling',flush=True)\n        until=time.monotonic()+5400;last_progress=time.monotonic()")
    root=once(root,"            request=wire_recv(sock);op=request.get('op')","            request=wire_recv(sock);op=request.get('op')\n            if time.monotonic()-last_progress>=60:\n                print('ROOT_HEARTBEAT=supervising_original_256_recheck',flush=True);last_progress=time.monotonic()")
    root=once(root,"                temporary=config.with_name('runtime.toml.cow4-restore-'+plan['run_id'])","                print('ROOT_PHASE=restore_original_configuration',flush=True)\n                temporary=config.with_name('runtime.toml.cow4-restore-'+plan['run_id'])")
    root=once(root,"                os.replace(temporary,config)","                os.replace(temporary,config)\n                require(hashlib.sha256(scoped_read(config)).hexdigest()==plan['original_config_sha256'],'Restored configuration bytes differ')\n                cm=config.stat()\n                require({'uid':cm.st_uid,'gid':cm.st_gid,'mode':stat.S_IMODE(cm.st_mode)}==expected_meta,'Restored configuration metadata differs')")
    root=once(root,"                report['original_configuration_restored']=True\n                report['original_service_healthy']=True","                verify_original_server(plan,restored)\n                report['original_server_unchanged']=True\n                report['original_configuration_restored']=True\n                report['original_service_healthy']=True")
    root=(HERE/'recheck256_root.py').read_text(encoding='utf-8')+'\n'+root
    compile(root,'original-256-root','exec')
    addition='\n'
    for name,data in [('recheck256_owner',(HERE/'recheck256_owner.py').read_bytes()),('recheck256_root',root.encode())]:
        addition+='EMBEDDED['+repr(name)+']='+repr({'sha256':hashlib.sha256(data).hexdigest(),'base64':base64.b64encode(data).decode()})+'\n'
    addition+="RECHECK=_module('recheck256_owner')\nROOT_SOURCE=_source('recheck256_root')\n"
    packet=(text+addition+"\nif __name__=='__main__':"+footer.replace('STOPPED_COW4_GLOBAL_ENTRY','STOPPED_COW4_ORIGINAL_256_RECHECK_ENTRY')).encode()
    compile(packet,'cow4-original-256-recheck','exec')
    (HERE.parent/'cow4_original_256_recheck.py').write_bytes(packet)
    return {'sha256':hashlib.sha256(packet).hexdigest(),'bytes':len(packet),'root_literal_sha256':hashlib.sha256(root.encode()).hexdigest()}


if __name__=='__main__':print(json.dumps(generate(Path(sys.argv[1])),indent=2))
