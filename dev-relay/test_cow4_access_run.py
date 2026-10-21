import ast, copy, importlib.util, json, tempfile, unittest
import types
from pathlib import Path, PurePosixPath
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('four_packet',HERE/'cow4_access_once.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class FourRunTests(unittest.TestCase):
    def test_config_only_replaces_daemon(self):
        with patch.object(m.ENGINE,'BASE',PurePosixPath('/original')):
            raw=b'other = true\n[ublk]\ndaemon_binary_path = "/original/bin/uvm-ublk-daemon"\nstartup_prewarm = false\n'
            changed=m.replace_daemon(raw,PurePosixPath('/owned/observer/daemon'))
            self.assertEqual(changed.replace(b'/owned/observer/daemon',b'/original/bin/uvm-ublk-daemon'),raw)
            with self.assertRaises(RuntimeError):m.replace_daemon(raw+b'daemon_binary_path = "other"\n',PurePosixPath('/owned/observer/daemon'))
    def test_selection_is_four_first_batch_existing_templates(self):
        cases=[];built=[]
        for lang in ('go','ts','java'):
            for i in range(3):
                n=lang+str(i);cases.append({'instance_id':n,'language':lang,'recorded_wait_seconds':i})
                built.append({'instance_id':n,'template_id':n,'state':'READY'})
        selected,_=m.choose({'cohort':{'cases':cases}},{'cases':built},{'jobs':[{'instance_id':c['instance_id']} for c in cases]})
        self.assertEqual([c['instance_id'] for c in selected],['go0','go1','ts0','java0'])
    def test_ranges_preserve_page_identity_not_payload(self):
        self.assertEqual(m.compact_ranges({(1,2,0),(1,2,1),(1,2,3),(1,3,0)}),{'1:2':[[0,2],[3,1]],'1:3':[[0,1]]})
    def test_phase_freezes_completed_guest(self):
        r=object.__new__(m.FourRun);r.ends={}
        self.assertEqual(r.phase(['a','b']),'both_replaying');r.ends['a']=100
        self.assertEqual(r.phase(['a','b']),'mixed_running_idle');r.ends['b']=200
        self.assertEqual(r.phase(['a','b']),'after_replay')
    def test_packet_only_adds_four_budget_to_original_engine(self):
        raw=(HERE/'cow55_replay.py').read_bytes().decode()
        self.assertEqual(m._source('engine'),raw.replace('template_count in (16,17,55)','template_count in (4,16,17,55)'))
    def test_root_source_has_only_fixed_unit_restart(self):
        tree=ast.parse(m.ROOT_SOURCE)
        calls=[n for n in ast.walk(tree) if isinstance(n,ast.List) and len(n.elts)>=2 and isinstance(n.elts[0],ast.Constant) and n.elts[0].value=='/usr/bin/systemctl']
        actions=[]
        for n in calls:
            action=n.elts[1].value;actions.append(action)
            if action=='restart':self.assertIsInstance(n.elts[2],ast.Name);self.assertEqual(n.elts[2].id,'UNIT')
        self.assertEqual(actions.count('restart'),2)
        self.assertTrue(set(actions)<= {'show','list-units','restart'})
        strings=[n.value for n in ast.walk(tree) if isinstance(n,ast.Constant) and isinstance(n.value,str)]
        for forbidden in ('modprobe','rmmod','drop_caches','sudo'):self.assertNotIn(forbidden,strings)
    def test_rpc_rejects_early_restoration_during_sample(self):
        r=object.__new__(m.FourRun);r.sock=object()
        with patch.object(m.ENGINE,'send'),patch.object(m.ENGINE,'receive',return_value={'op':'restored'}):
            with self.assertRaises(RuntimeError):r.rpc('sample')
    def test_completed_window_does_not_silently_drop_start_straddler(self):
        a=m.ACCOUNTING
        header={'kind':'header','version':1,'pid':1,'clock':'CLOCK_MONOTONIC','build_patch_sha256':'x'}
        row={'kind':'read','seq':0,'source':'s','dev':1,'inode':2,'file_bytes':8192,'offset':0,'bytes':4096,
             'direct_io':False,'allowed_lower':True,'start_ns':90,'end_ns':110}
        status={'pid':1,'mono_ns':210,'records_written':1,'dropped_records':0,'errors':0,'unsupported_context_calls':0}
        args=(status,{'s':{'sandbox_id':'a','lower_keys':{(1,2)},'upper_keys':set()}},{'a':(100,200)},{(1,2):{'file_bytes':8192}},'x')
        with self.assertRaises(ValueError):a.read_sets(iter(map(json.dumps,[header,row])),*args)
        sets,audit=a.read_sets(iter(map(json.dumps,[header,row])),*args,window_semantics='completion')
        self.assertEqual(sets['a'],{(1,2,0)});self.assertEqual(audit['boundary_crossing'],1)
    def test_root_wrong_host_cannot_enter_restore_path(self):
        ns={'require':m.ENGINE.need,'UNIT':'jwk-aenv-ae9c626-node-a.service','BASE':Path('/fixed/original')}
        exec(compile(m.ROOT_SOURCE,'root-session','exec'),ns)
        with patch.object(ns['os'],'geteuid',return_value=0,create=True),patch.object(ns['os'],'uname',return_value=types.SimpleNamespace(nodename='other'),create=True),patch.object(ns['subprocess'],'run') as command,patch('builtins.print'):
            ns['root_session']({'run_id':'x','original_config_base64':''})
        command.assert_not_called()
    def test_root_wrong_original_bytes_cannot_restart(self):
        ns={'require':m.ENGINE.need,'UNIT':'jwk-aenv-ae9c626-node-a.service','BASE':Path('/fixed/original')}
        exec(compile(m.ROOT_SOURCE,'root-session','exec'),ns)
        with patch.object(ns['os'],'geteuid',return_value=0,create=True),patch.object(ns['os'],'uname',return_value=types.SimpleNamespace(nodename='server1'),create=True),patch.object(ns['subprocess'],'run') as command,patch('builtins.print'):
            ns['root_session']({'run_id':'x','original_config_base64':'','original_config_sha256':m.CONFIG_SHA})
        command.assert_not_called()


if __name__=='__main__':unittest.main()
