"""Generate the IO64 trial from the byte-pinned, already executed baseline packet.

Usage: python make_trial.py /path/to/cow4_global_cache_once.py
"""
import ast, base64, hashlib, importlib.util, json, sys
from pathlib import Path

HERE=Path(__file__).resolve().parent
BASE_PACKET_SHA='4dc486145378f945df9a285e9bee0fe7368c147a67699b3343ce47bc8200ceb1'


def once(s,a,b):
    assert s.count(a)==1,a
    return s.replace(a,b)


def generate(path):
    raw=path.read_bytes();assert hashlib.sha256(raw).hexdigest()==BASE_PACKET_SHA
    spec=importlib.util.spec_from_file_location('executed_global_baseline',path)
    old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
    source=raw.decode();body,footer=source.rsplit("if __name__=='__main__':",1)
    tree=ast.parse(body);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main')
    before=ast.get_source_segment(body,node);main=before
    main=once(main,"m.PENDING=m.ROOT/'relay/cow4-global-cache-v2-node-a.pending.json'","m.PENDING=m.ROOT/'relay/cow4-original-io64-node-a.pending.json'")
    main=once(main,"m.ROOT/'relay/cow4-rootfs-access-build-v2.json'","m.ROOT/'relay/cow4-original-rootfs-io64-build.json'")
    main=once(main,"receipt['status']=='ROOTFS_ACCESS_OBSERVER_BUILT_AND_CALIBRATED_NOT_DEPLOYED'","receipt['status']=='ORIGINAL_ROOTFS_IO64_BUILT_AND_CALIBRATED_NOT_DEPLOYED'")
    main=once(main,'retry=BASELINE.reconcile(m,identity,api)','retry=IO64.reconcile(m,identity,api)')
    main=once(main,"prefix='node-a-cow4-global-'","prefix='node-a-cow4-io64-'")
    main=once(main,"selected,built=choose(inputs,build,previous)","selected,built=choose(inputs,build,previous)\n    m.need(sorted(b['template_id'] for b in built)==retry['baseline_template_ids'],'Template selection differs from 256 KiB baseline')")
    main=once(main,"revision='cow4-global-cache-v2',variant='original_with_diagnostic_observer'","revision='cow4-original-io64-v1',variant='original_rootfs_io64_with_diagnostic_observer'")
    main=once(main,"Path(BUILD_WORK)/'candidate/uvm-ublk-daemon-observe'","Path(BUILD_WORK)/'observer/uvm-ublk-daemon-observe'")
    main=once(main,"    files={};template_lowers={}","    server_plan=IO64.prepare_server(m,work,receipt,identity)\n    files={};template_lowers={}")
    main=once(main,'    cohort.report.update(root_plan=plan,template_lowers=template_lowers,',"    plan.update(server_plan)\n    plan['baseline_run_id']=IO64.BASELINE_RUN\n    cohort.report.update(root_plan=plan,template_lowers=template_lowers,")
    main=main.replace('COW4_GLOBAL_V2_ROOT','COW4_ORIGINAL_IO64_ROOT')
    main=once(main,'then restores exact original configuration. No done input.','temporarily replaces the original server with the pinned original-only IO64 candidate, then restores exact original server bytes and configuration. No done input.')
    main=once(main,"and restored.get('observer_exit_confirmed') and cohort.report['cache_crosscheck_passed']", "and restored.get('observer_exit_confirmed') and restored.get('original_server_bytes_and_metadata_restored') and restored.get('rootfs64_memory256_verified') and cohort.report['cache_crosscheck_passed']")
    main=once(main,"                result['validation']={'status':", "                result['implementation']='original_rootfs_io64_with_diagnostic_observer'\n                result['experiment_comparison']={'baseline_run_id':IO64.BASELINE_RUN,'base_commit':'ae9c62693839ce7effa2b45df31c0039ae4f9fbc','core_commit':IO64.CORE_COMMIT,'rootfs_max_io_kib':64,'memory_max_io_kib':256,'server_sha256':IO64.SERVER_SHA,'daemon_sha256':IO64.DAEMON_SHA,'observer_patch_sha256':PATCH_SHA,'effective_limits':restored.get('effective_device_limits'),'scope':'Rootfs ublk max I/O only; remote refill and read observer unchanged; not a UB trial'}\n                result['validation']={'status':")
    main=main.replace('COW4_POST_DROP_BASELINE_MEASURED_GUESTS_RELEASED_ORIGINAL_RESTORED','COW4_IO64_MEASURED_GUESTS_RELEASED_ORIGINAL_RESTORED')
    body=once(body,before,main)
    root=old.ROOT_SOURCE
    root=once(root,"        before=unit_state();assert_unit(before)","        print('ROOT_PHASE=preflight_original_and_candidate',flush=True)\n        before=unit_state();assert_unit(before)\n        io64_server_preflight(plan,before)\n        report.update(original_server_sha256=plan['original_server_sha256'],candidate_server_sha256=IO64_SERVER_SHA,core_commit=plan['core_commit'])")
    root=once(root,"expected_new=re.sub(pattern,lambda _: 'daemon_binary_path = '+json.dumps(str(candidate)),raw.decode()).encode()","expected_new=io64_config(raw,candidate)")
    root=once(root,"'Configuration delta exceeds daemon path only'","'Configuration delta exceeds daemon path and rootfs I/O limit'")
    root=once(root,"=='eed36d01de13f83a8abdc13e93c21883a3a48273da83fa1c813e65e4655babcf'","==IO64_DAEMON_SHA")
    root=once(root,"        wire_send(sock,{'op':'ready'})","        print('ROOT_PHASE=ready_for_owner',flush=True)\n        wire_send(sock,{'op':'ready'})")
    root=once(root,'        # Only this existing original unit is restarted, never stopped/unloaded.',"        print('ROOT_PHASE=activate_original_io64',flush=True)\n        io64_install_server(plan,report)\n        # Only this existing original unit is restarted, never stopped/unloaded.")
    root=once(root,'        active=wait_health();assert_unit(active)','        active=wait_health();assert_unit(active)\n        io64_active_server(plan,active)')
    root=once(root,"        bound.append({'sandbox_id':b['sandbox_id']","        limits=io64_bound_devices(b)\n        bound.append({'effective_device_limits':limits,'sandbox_id':b['sandbox_id']")
    root=once(root,"                report['observer_identity']=[pid,ticks]","                report['observer_identity']=[pid,ticks]\n                report['effective_device_limits']=[{'sandbox_id':b['sandbox_id'],'template_id':b['template_id'],**b['effective_device_limits']} for b in bound]\n                report['rootfs64_memory256_verified']=len(bound)==8\n                print('ROOT_PHASE=rootfs64_memory256_verified_8_of_8',flush=True)")
    root=once(root,'        until=time.monotonic()+5400',"        print('ROOT_PHASE=waiting_for_guests_and_sampling',flush=True)\n        until=time.monotonic()+5400;last_progress=time.monotonic()")
    root=once(root,"            request=wire_recv(sock);op=request.get('op')","            request=wire_recv(sock);op=request.get('op')\n            if time.monotonic()-last_progress>=60:\n                print('ROOT_HEARTBEAT=supervising_io64_trial',flush=True);last_progress=time.monotonic()")
    root=once(root,"                temporary=config.with_name('runtime.toml.cow4-restore-'+plan['run_id'])","                print('ROOT_PHASE=restore_original_server_and_config',flush=True)\n                io64_restore_server(plan,report)\n                temporary=config.with_name('runtime.toml.cow4-restore-'+plan['run_id'])")
    root=once(root,"                report['original_configuration_restored']=True\n                report['original_service_healthy']=True","                io64_verify_original(plan,BASE/'bin/server')\n                a=(Path('/proc')/restored['MainPID']/'exe').stat();b=(BASE/'bin/server').stat()\n                require((a.st_dev,a.st_ino)==(b.st_dev,b.st_ino),'Restored process is not original server inode')\n                report['original_configuration_restored']=True\n                report['original_service_healthy']=True")
    root=once(root,"            elif current_hash==plan['original_config_sha256'] and not changed:\n                report['original_configuration_restored']=True","            elif current_hash==plan['original_config_sha256'] and not changed:\n                io64_restore_server(plan,report)\n                report['original_configuration_restored']=True")
    root=once(root,"                os.replace(temporary,config)","                os.replace(temporary,config)\n                require(hashlib.sha256(scoped_read(config)).hexdigest()==plan['original_config_sha256'],'Restored configuration bytes differ')\n                cm=config.stat()\n                require({'uid':cm.st_uid,'gid':cm.st_gid,'mode':stat.S_IMODE(cm.st_mode)}==expected_meta,'Restored configuration metadata differs')")
    root_extra=(HERE/'root_binary.py').read_bytes();owner=(HERE/'owner_trial.py').read_bytes()
    root=root_extra.decode()+'\n'+root
    compile(root,'literal-io64-root','exec')
    payloads={'io64_owner':owner,'io64_root_extra':root_extra,'io64_root_session':root.encode()}
    addition='\n'
    for key,data in payloads.items():
        addition+='EMBEDDED['+repr(key)+']='+repr({'sha256':hashlib.sha256(data).hexdigest(),'base64':base64.b64encode(data).decode()})+'\n'
    addition+="""
IO64=_module('io64_owner')
IO64_CONFIG=_module('io64_root_extra')
IO64_CONFIG.__dict__.update({'require':ENGINE.need,'BASE':ENGINE.BASE,'json':json,'re':re})
ROOT_SOURCE=_source('io64_root_session')
CANDIDATE_SHA=IO64.DAEMON_SHA
BUILD_WORK='/home/jwk/agent/relay/reports/node-a-original-rootfs-io64-build-5dwoe1n5'
def replace_daemon(raw,candidate):return IO64_CONFIG.io64_config(raw,candidate)
"""
    packet=(body+addition+"\nif __name__=='__main__':"+footer.replace('STOPPED_COW4_GLOBAL_ENTRY','STOPPED_COW4_ORIGINAL_IO64_ENTRY')).encode()
    compile(packet,'cow4-original-io64-once','exec')
    output=HERE.parent/'cow4_original_io64_once.py';output.write_bytes(packet)
    return {'sha256':hashlib.sha256(packet).hexdigest(),'bytes':len(packet),'literal_root_sha256':hashlib.sha256(root.encode()).hexdigest()}


if __name__=='__main__':print(json.dumps(generate(Path(sys.argv[1])),indent=2))
