"""Portable accounting/control checks; no claim of Linux or target execution."""
import ast,base64,contextlib,hashlib,importlib.util,io,json,os,re,socket,stat,types,unittest,uuid
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent


def load(path,name):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m


PACKET=load(HERE.parent/'cow4_memory_pair.py','memory_packet')
PATCHER=PACKET.module('memory_patches',PACKET.payload('patch_sources'))
OLD={256:load(HERE.parent/'cow4_original_256_recheck.py','old256'),64:load(HERE.parent/'cow4_original_io64_once.py','old64')}
ROOT_SOURCE=PATCHER.root_source(OLD[64].ROOT_SOURCE,PACKET.payload('root256_extra'),PACKET.payload('root_measure'),PACKET.payload('root_pair'))


def require(ok,why):
    if not ok:raise RuntimeError(why)


class Tests(unittest.TestCase):
    def setUp(self):
        self.context=contextlib.ExitStack();self.addCleanup(self.context.close)
        if os.name=='nt':
            original=Path.__str__;self.context.enter_context(patch.object(Path,'__str__',lambda p:original(p).replace('\\','/')))

    def root(self):
        ns={'require':require,'identity':lambda p:(1,'t'+str(p)),'UNIT':'test.service','ROOT':Path('/scope'),'BASE':Path('/base')}
        exec(ROOT_SOURCE,ns);return ns

    def stage(self,mode):
        raw=(HERE.parent/('cow4_original_256_recheck.py' if mode==256 else 'cow4_original_io64_once.py')).read_text(encoding='utf-8')
        return PACKET.module('test_stage'+str(mode),PATCHER.stage_source(raw,mode,PACKET.payload('owner_extension')),{'MODE':mode,'MASTER':None,'PAIR_ID':'pair-fixture'})

    def test_exact_old_packets_and_literal_compile(self):
        for mode,name in ((256,'cow4_original_256_recheck.py'),(64,'cow4_original_io64_once.py')):
            raw=(HERE.parent/name).read_bytes();self.assertEqual(hashlib.sha256(raw).hexdigest(),PACKET.PACKETS[mode][1])
            s=self.stage(mode)
            self.assertTrue(issubclass(s.FourRun,s.GlobalFourRun));self.assertEqual(s.PATCH_SHA,OLD[mode].PATCH_SHA)
            self.assertEqual(s.EMBEDDED,OLD[mode].EMBEDDED)
        self.assertIn("memory_mode(plan)==64",ROOT_SOURCE)
        self.assertNotIn('exec(',ROOT_SOURCE)
        self.assertNotIn('eval(',ROOT_SOURCE)
        def functions(text):return {n.name:ast.dump(n) for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
        old=functions(OLD[64].ROOT_SOURCE);new=functions(ROOT_SOURCE)
        for name in ('global_drop_once','io64_install_server','io64_restore_server','io64_active_server','io64_device_limit','other_units','scoped_read'):
            self.assertEqual(old[name],new[name],name)

    def test_changed_patch_anchor_refused(self):
        with self.assertRaises(RuntimeError):PATCHER.stage_source('def main():\n    return 0\n',256,'')

    def test_mode_config_only64_changes_io(self):
        n=self.root();raw=b'[ublk]\ndaemon_binary_path = "/base/bin/uvm-ublk-daemon"\n'
        a=n['memory_runtime_config']({'rootfs_io_kib':256},raw,Path('/candidate'))
        b=n['memory_runtime_config']({'rootfs_io_kib':64},raw,Path('/candidate'))
        self.assertNotIn(b'rootfs_max_io_kib',a);self.assertIn(b'rootfs_max_io_kib = 64',b)
        for mode in (True,128,'64'):
            with self.assertRaises(RuntimeError):n['memory_mode']({'rootfs_io_kib':mode})

    def test_single_status_rollup_read_and_missing_category_na(self):
        n=self.root();calls=[]
        def read(pid,name,limit):
            calls.append(name);return 'VmRSS: 100 kB\nRssAnon: 80 kB\nRssFile: 20 kB\n' if name=='status' else 'Rss: 100 kB\nPss: 90 kB\nPss_Anon: 80 kB\nPss_File: 10 kB\nPss_Shmem: 0 kB\n'
        n['proc_text']=read;r=n['whole_process_metrics'](4,'t4')
        self.assertEqual(calls,['status','smaps_rollup']);self.assertTrue(r['available']);self.assertTrue(r['pss_categories_complete'])
        self.assertEqual(r['pss_bytes'],r['rollup_bytes']['Pss']);self.assertEqual(r['rss_minus_pss_bytes'],10*1024)
        n['proc_text']=lambda *a:'VmRSS: 100 kB\nRss: 100 kB\nPss: 90 kB\n'
        r=n['whole_process_metrics'](4,'t4');self.assertTrue(r['available']);self.assertFalse(r['pss_categories_complete']);self.assertIsNone(r['rollup_bytes']['Pss_File'])

    def test_private_cow_with_file_name_not_lost(self):
        n=self.root();n['proc_text']=lambda *a:'1000-3000 rw-p 00000000 00:00 1 /dev/ublkb1\nRss: 8 kB\nPss: 6 kB\nAnonymous: 4 kB\nPrivate_Dirty: 4 kB\n3000-4000 rw-p 00000000 00:00 0 [heap]\nRss: 4 kB\nPss: 4 kB\n'
        n['parse_guest_smaps']=lambda *a:[{'start':4096,'end':12288,'mapping_kind':'snapshot_file_vma','bytes':{'Rss':8192,'Pss':6144,'Anonymous':4096,'Private_Dirty':4096}}]
        b={'pid':4,'start_ticks':'t4','sandbox_id':'s','template_id':'t','memory_device':'/dev/ublkb1','guest_regions':[{'base_host_virt_addr':4096,'size':8192}]}
        r=n['ram_classification'](b);self.assertTrue(r['exact_vma_partition']);self.assertEqual(r['snapshot_named_vma']['metrics']['Anonymous'],4096);self.assertEqual(r['fc_outside_guest_ram']['metrics']['Pss'],4096)
        n['parse_guest_smaps']=lambda *a:[{'start':4096,'end':8192,'mapping_kind':'snapshot_file_vma','bytes':{},'smaps_metrics_omitted_due_to_clipping':True}]
        r=n['ram_classification'](b);self.assertFalse(r['exact_vma_partition']);self.assertIsNone(r['guest_ram']['metrics']['Pss'])

    def test_devices_deduplicated_and_post_exit_not_zero(self):
        n=self.root();rows=[{'pid':i,'start_ticks':'t'+str(i),'sandbox_id':'s'+str(i),'template_id':'t'+str(i//2),'memory_device':'/dev/ublkb'+str(i//2),'memory_device_identity':[1,i//2,100+i//2]} for i in range(8)]
        calls=[]
        n['resident']=lambda p,*a:(calls.append(str(p)) or {'available':True,'resident_page_bytes':4096})
        def meta(p,*a,**kw):
            idx=int(p.name.removeprefix('ublkb'));return types.SimpleNamespace(st_mode=stat.S_IFBLK,st_dev=1,st_ino=idx,st_rdev=100+idx)
        with patch.object(Path,'stat',meta):r=n['memory_devices'](rows)
        self.assertEqual(len(calls),4);self.assertEqual(r['unique_resident_bytes'],4*4096)
        self.assertIsNone(n['memory_devices']([])['unique_resident_bytes'])
        rows[0]['memory_device_identity']=[1,999,100]
        with patch.object(Path,'stat',meta):r=n['memory_devices'](rows)
        self.assertFalse(r['all_available']);self.assertIsNone(r['unique_resident_bytes'])

    def test_pfn_instability_is_na(self):
        n=self.root();calls=[]
        n['parse_guest_smaps']=lambda *a:[];n['proc_text']=lambda *a:''
        def pm(*a):calls.append(1);return {1},{1},{'identity_hash':str(len(calls))}
        n['pagemap']=pm
        b=[{'pid':i,'start_ticks':'t'+str(i),'sandbox_id':'s'+str(i),'template_id':'t'+str(i//2),'memory_device':'/dev/ublkb0','guest_regions':[]} for i in range(8)]
        with patch.object(os,'sysconf',lambda x:4096,create=True):r=n['pfn_checkpoint'](b,'fixture')
        self.assertFalse(r['available']);self.assertTrue(all(not x['available'] for x in r['pairs']));self.assertNotIn('ordinary_mapped_unique_bytes',r)

    def test_pfn_global_counts_exclude_special_pages(self):
        n=self.root();n['parse_guest_smaps']=lambda *a:[];n['proc_text']=lambda *a:''
        n['pagemap']=lambda pid,*a:({pid+100,900,901},{pid+100,900,901},{'identity_hash':str(pid)})
        n['page_flags']=lambda pfns:{p:(1<<24) if p==901 else 0 for p in pfns}
        n['sharing']=lambda *a:{'fixture':'existing pair classifier is independently preserved'}
        b=[{'pid':i,'start_ticks':'t'+str(i),'sandbox_id':'s'+str(i),'template_id':'t'+str(i//2),'memory_device':'/dev/ublkb0','guest_regions':[]} for i in range(8)]
        with patch.object(os,'sysconf',lambda x:4096,create=True):r=n['pfn_checkpoint'](b,'fixture')
        self.assertTrue(r['available']);self.assertEqual(r['ordinary_mapped_unique_bytes'],9*4096)
        self.assertEqual(r['ordinary_shared_by_at_least_two_selected_Guests_bytes'],4096);self.assertEqual(r['ordinary_duplicate_mapping_bytes'],7*4096)
        self.assertEqual(r['special_or_unclassified_unique_bytes'],4096)

    def test_second_group_input_change_stops_before_announcement(self):
        s=self.stage(64);prior={'root_plan':{'template_lowers':{'different':[]}}}
        s.ENGINE.B=types.SimpleNamespace(read_json=lambda p:prior)
        with self.assertRaisesRegex(RuntimeError,'Paired input changed'):
            s.announce_memory_group({'template_lowers':{}},None)

    def test_same_cycle_pss_not_sum_of_independent_peaks(self):
        s=self.stage(256);d=Path.cwd()/'outputs/memory-pair-tests'/uuid.uuid4().hex;(d/'measurements').mkdir(parents=True)
        data=[]
        for cycle in range(2):
            for t in range(4):
                ps=[{'available':True,'pss_categories_complete':True,'pss_bytes':100 if (i+cycle)%2 else 1,'rss_bytes':200,'sandbox_id':str(t*2+i)} for i in range(2)]
                data.append({'sample_id':str(cycle),'template_id':str(t),'phase':'both_replaying','started_unix':cycle,'finished_unix':cycle+.1,'processes':ps})
        (d/'measurements/process.jsonl').write_text('\n'.join(json.dumps(x) for x in data),encoding='utf-8')
        s.ENGINE.H=types.SimpleNamespace(save=lambda p,v:p.write_text(json.dumps(v),encoding='utf-8'))
        out=s.memory_summary(d,{'run_id':'fixture'});r=json.loads((d/'memory-accounting-summary.json').read_bytes())
        self.assertEqual([x['sum_fc_pss_bytes'] for x in r['all_fc_same_cycle']],[404,404]);self.assertFalse(out['coverage']['required_accounting_complete'])
        self.assertFalse(out['coverage']['PFN_diagnostic_complete'])

    def lifecycle(self,mode,fault=None):
        d=Path.cwd()/'outputs/memory-pair-tests'/uuid.uuid4().hex;base=d/'base';work=d/'work'
        for p in (base/'bin',base/'config',work/'observer',d/'r'):p.mkdir(parents=True,exist_ok=True)
        installed=base/'bin/server';installed.write_bytes(b'original fixture');os.chmod(installed,0o755);oldmeta=installed.stat()
        backup=work/'server.original';os.link(installed,backup)
        server=work/'observer/server-rootfs-io64';server.write_bytes(b'candidate fixture')
        daemon=work/'observer/uvm-ublk-daemon-observe';daemon.write_bytes(b'daemon fixture');daemon.with_suffix('.access-spec').write_bytes(b'spec')
        raw=('[ublk]\ndaemon_binary_path = '+json.dumps(str(base/'bin/uvm-ublk-daemon'),ensure_ascii=False)+'\n').encode();config=base/'config/runtime.toml';config.write_bytes(raw)
        sha=lambda b:hashlib.sha256(b).hexdigest();run='a'*32;endpoint=d/'r'/('c4-'+run[:12]+'.sock');state={'pid':'10','restarts':0,'requests':0}
        n={'require':require,'ROOT':d,'BASE':base,'UNIT':'test.service','identity':lambda p:(1,'t'+str(p))}
        exec(ROOT_SOURCE.replace('f2a1abe6542c3230bfe3cd81b884cf080dc4a3b2f2c371b40092940c686d01bd',sha(raw)),n)
        n.update(IO64_SERVER_SHA=sha(server.read_bytes()),IO64_DAEMON_SHA=sha(daemon.read_bytes()),ORIGINAL_OBSERVER_SHA=sha(daemon.read_bytes()),ORIGINAL_SERVER_SHA=sha(installed.read_bytes()))
        cm=config.stat();plan={'rootfs_io_kib':mode,'run_id':run,'work':str(work),'core_commit':'fixture','candidate':str(daemon),'candidate_sha256':sha(daemon.read_bytes()),'server_candidate':str(server),'server_sha256':sha(server.read_bytes()),'original_server_backup':str(backup),'original_server_sha256':sha(installed.read_bytes()),'original_server_metadata':n['io64_meta'](installed),'original_config_base64':base64.b64encode(raw).decode(),'original_config_sha256':sha(raw),'original_config_metadata':{'uid':cm.st_uid,'gid':cm.st_gid,'mode':stat.S_IMODE(cm.st_mode)},'original_identity':[10,'t10'],'boot_id':'boot','endpoint':str(endpoint),'spec_sha256':sha(b'spec')}
        new=n['memory_runtime_config'](plan,raw,daemon);plan['new_config_sha256']=sha(new)
        unit=lambda:{'MainPID':state['pid'],'ticks':'t'+state['pid'],'ActiveState':'active'}
        n.update(unit_state=unit,assert_unit=lambda s:None,other_units=lambda:{'other':'same'},scoped_read=lambda p,limit=65536:p.read_bytes(),check_peer=lambda *a:None,
                 api_get=lambda p:(204,None) if p=='/health' else ((200,[{}]) if fault=='remaining' and state['requests']>=2 else (200,[])),
                 memory_snapshot=lambda *a:{'phase':a[-1],'complete':True})
        def send(sock,v):
            if v['op']=='ready':config.write_bytes(new)
        def recv(sock):
            state['requests']+=1
            if state['requests']==1:return {'op':'activate'}
            if fault=='unknown':installed.write_bytes(b'unknown')
            return {'op':'restore'} if state['requests']==2 else {'op':'cleanup_complete'}
        n.update(wire_send=send,wire_recv=recv)
        def restart(cmd,**kw):
            self.assertEqual(cmd,['/usr/bin/systemctl','restart','test.service']);state['restarts']+=1;state['pid']=str(10+state['restarts']);return types.SimpleNamespace(returncode=0)
        realstat=Path.stat;realread=Path.read_text;reallstat=Path.lstat
        def met(p,*a,**kw):return realstat(installed) if str(p).startswith('/proc/') and p.name=='exe' else realstat(p,*a,**kw)
        def read(p,*a,**kw):return 'boot' if p.name=='boot_id' else realread(p,*a,**kw)
        def lst(p,*a,**kw):return types.SimpleNamespace(st_mode=stat.S_IFSOCK|0o600,st_uid=1204) if p==endpoint else reallstat(p,*a,**kw)
        sock=types.SimpleNamespace(settimeout=lambda x:None,connect=lambda x:None,close=lambda:None)
        with patch.object(Path,'stat',met),patch.object(Path,'read_text',read),patch.object(Path,'lstat',lst),patch.object(os,'geteuid',lambda:0,create=True),patch.object(os,'uname',lambda:types.SimpleNamespace(nodename='server1'),create=True),patch.object(os,'O_NOFOLLOW',0,create=True),patch.object(os,'fchown',lambda *a:None,create=True),patch.object(os,'fchmod',lambda *a:None,create=True),patch.object(socket,'socket',lambda *a:sock),patch.object(socket,'AF_UNIX',1,create=True),patch.object(n['subprocess'],'run',restart),patch.object(n['time'],'sleep',lambda s:None),contextlib.redirect_stdout(io.StringIO()):
            r=n['root_session'](plan)
        if fault:
            self.assertEqual(state['restarts'],1,r);self.assertIn('restoration_error',r)
            self.assertEqual(backup.read_bytes(),b'original fixture')
            if fault=='unknown':self.assertEqual(installed.read_bytes(),b'unknown')
        else:
            self.assertEqual(state['restarts'],2,r);self.assertEqual(r['status'],'COW4_ROOT_SESSION_RESTORED');self.assertEqual(config.read_bytes(),raw);self.assertEqual(installed.stat().st_ino,oldmeta.st_ino)
            self.assertIn('T4_original_service_restored',r['memory_baselines'])
            if mode==256:self.assertFalse(r['server_binary_replaced']);self.assertTrue(r['original_server_unchanged'])
            else:self.assertTrue(r['original_server_bytes_and_metadata_restored'])

    def test_256_activation_and_exact_restore(self):self.lifecycle(256)
    def test_64_activation_and_exact_restore(self):self.lifecycle(64)
    def test_remaining_guest_prevents_restart(self):self.lifecycle(64,'remaining')
    def test_unknown_binary_not_overwritten(self):self.lifecycle(64,'unknown')

    def driver(self,mode_order=(256,64),first_owner_complete=True):
        n=self.root();pair='a'*32;master={'pair_id':pair,'endpoint':'/scope/r/cm-'+pair[:12]+'.sock','owner_pid':7,'owner_ticks':'t7'}
        requests=[];seen=[];sent=[]
        for mode in mode_order:
            plan=dict(master,rootfs_io_kib=mode,work='/scope/relay/reports/node-a-memory-'+str(mode)+'-fixture',run_id='run'+str(mode))
            requests.extend([{'op':'start_group','plan':plan},{'op':'group_complete','rootfs_io_kib':mode,'lifecycle_complete':first_owner_complete if mode==256 else True}])
        def group(plan):
            seen.append(plan['rootfs_io_kib']);return {'status':'COW4_ROOT_SESSION_RESTORED','original_configuration_restored':True,'original_service_healthy':True,'other_services_unchanged':True}
        n.update(root_session=group,wire_recv=lambda s:requests.pop(0),wire_send=lambda s,v:sent.append(v),check_peer=lambda *a:None)
        sock=types.SimpleNamespace(settimeout=lambda x:None,connect=lambda x:None,close=lambda:None)
        with patch.object(Path,'lstat',lambda p:types.SimpleNamespace(st_mode=stat.S_IFSOCK|0o600,st_uid=1204)),patch.object(os,'geteuid',lambda:0,create=True),patch.object(os,'uname',lambda:types.SimpleNamespace(nodename='server1'),create=True),patch.object(socket,'socket',lambda *a:sock),patch.object(socket,'AF_UNIX',1,create=True),contextlib.redirect_stdout(io.StringIO()):
            r=n['memory_root_driver'](master)
        return r,seen,sent

    def test_two_stage_driver_order_and_final_receipt(self):
        r,seen,sent=self.driver();self.assertEqual(seen,[256,64]);self.assertEqual(r['status'],'MEMORY_PAIR_ROOT_BOTH_GROUPS_RESTORED');self.assertEqual(sent[-1]['op'],'pair_root_finished')

    def test_first_group_failure_prevents_second(self):
        r,seen,_=self.driver(first_owner_complete=False);self.assertEqual(seen,[256]);self.assertEqual(r['status'],'MEMORY_PAIR_STOPPED_AFTER_GROUP_FAILURE')

    def test_wrong_order_rejected_before_activation(self):
        r,seen,_=self.driver((64,256));self.assertEqual(seen,[]);self.assertEqual(r['status'],'STOPPED_MEMORY_PAIR_ROOT')


if __name__=='__main__':unittest.main(verbosity=2)
