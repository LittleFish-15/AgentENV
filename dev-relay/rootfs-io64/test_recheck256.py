"""Portable original-256 admission checks; no Linux/Guest execution claim."""
import contextlib,copy,hashlib,importlib.util,json,os,re,stat,types,unittest,uuid
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('recheck256_packet',HERE.parent/'cow4_original_256_recheck.py')
PACKET=importlib.util.module_from_spec(spec);spec.loader.exec_module(PACKET)


def need(ok,why):
    if not ok:raise RuntimeError(why)


class Tests(unittest.TestCase):
    def setUp(self):
        self.context=contextlib.ExitStack();self.addCleanup(self.context.close)
        if os.name=='nt':
            original=Path.__str__;self.context.enter_context(patch.object(Path,'__str__',lambda p:original(p).replace('\\','/')))

    def receipt_fixture(self):
        flags=('original_server_bytes_and_metadata_restored','original_configuration_restored','original_service_healthy','other_services_unchanged','observer_exit_confirmed','bound_guest_processes_exited','rootfs64_memory256_verified')
        root=dict.fromkeys(flags,True);root.update(status='COW4_ROOT_SESSION_RESTORED',restored_identity=[42,'100'],original_server_sha256=hashlib.sha256(b'original').hexdigest())
        receipt={'run_id':PACKET.RECHECK.IO64_RUN,'status':'COW4_IO64_MEASURED_GUESTS_RELEASED_ORIGINAL_RESTORED','all_cohort_guests_released':True,'restore_outcome_uncertain':False,'replay_completed_guests':8,'root_session':root,
                 'jobs':[{'sandbox_id':'s'+str(i),'template_id':'t'+str(i//2)} for i in range(8)],'released_sandboxes':['s'+str(i) for i in range(8)],'observer_identity':[5,'10'],
                 'bindings':[{'pid':10+i,'start_ticks':'20'} for i in range(8)],'report_directory':'/reports/previous'}
        def gone(pid):raise FileNotFoundError('fixture old process exited')
        m=types.SimpleNamespace(ROOT=Path('/scope'),BASE=Path('/base'),B=types.SimpleNamespace(read_json=lambda p:copy.deepcopy(receipt)),R=types.SimpleNamespace(identity=gone),H=types.SimpleNamespace(read=lambda *a:b'original'))
        return receipt,m

    def test_completed_prior_run_and_original_bytes_admitted(self):
        receipt,m=self.receipt_fixture();before=copy.deepcopy(receipt)
        with patch.object(PACKET.RECHECK,'ORIGINAL_SERVER_SHA',hashlib.sha256(b'original').hexdigest()):
            result=PACKET.RECHECK.reconcile(m,[42,'100'],types.SimpleNamespace(call=lambda *a:(404,None)))
        self.assertEqual(result['baseline_template_ids'],['t0','t1','t2','t3']);self.assertEqual(receipt,before)

    def test_incomplete_restore_refused(self):
        receipt,m=self.receipt_fixture();receipt['root_session']['original_server_bytes_and_metadata_restored']=False
        with self.assertRaises(RuntimeError):PACKET.RECHECK.reconcile(m,[42,'100'],types.SimpleNamespace(call=lambda *a:(404,None)))

    def test_remaining_guest_refused(self):
        receipt,m=self.receipt_fixture()
        with patch.object(PACKET.RECHECK,'ORIGINAL_SERVER_SHA',hashlib.sha256(b'original').hexdigest()),self.assertRaises(RuntimeError):
            PACKET.RECHECK.reconcile(m,[42,'100'],types.SimpleNamespace(call=lambda *a:(200,{})))

    def test_changed_runtime_refused(self):
        _,m=self.receipt_fixture()
        with self.assertRaises(RuntimeError):PACKET.RECHECK.reconcile(m,[43,'101'],types.SimpleNamespace(call=lambda *a:(404,None)))

    def root_namespace(self):
        ns={'require':need,'Path':Path,'stat':stat,'re':re,'os':os,'hashlib':hashlib}
        exec((HERE/'recheck256_root.py').read_text(encoding='utf-8'),ns);return ns

    def test_effective_queue_requires_256_for_both_caps(self):
        ns=self.root_namespace();values={'max_hw_sectors_kb':256,'max_sectors_kb':256,'logical_block_size':512,'physical_block_size':4096,'read_ahead_kb':4096}
        with patch.object(Path,'resolve',lambda p,**k:p),patch.object(Path,'stat',lambda p,**k:types.SimpleNamespace(st_mode=stat.S_IFBLK,st_rdev=3)),patch.object(Path,'read_text',lambda p,**k:'240:3' if p.name=='dev' else str(values[p.name])),patch.object(os,'major',lambda n:240,create=True),patch.object(os,'minor',lambda n:3,create=True):
            self.assertEqual(ns['original_device_limit']('/dev/ublkb3')['expected_kib'],256)
            for key in ('max_hw_sectors_kb','max_sectors_kb'):
                values[key]=64
                with self.assertRaises(RuntimeError):ns['original_device_limit']('/dev/ublkb3')
                values[key]=256

    def test_original_binary_hash_and_inode_guard(self):
        directory=Path.cwd()/'outputs/rootfs-io256-recheck-20261022/tests'/uuid.uuid4().hex
        (directory/'bin').mkdir(parents=True);binary=directory/'bin/server';binary.write_bytes(b'original')
        s=binary.stat();ns=self.root_namespace();ns.update(BASE=directory,scoped_read=lambda p,limit:p.read_bytes(),ORIGINAL_SERVER_SHA=hashlib.sha256(b'original').hexdigest())
        plan={'original_server_sha256':ns['ORIGINAL_SERVER_SHA'],'original_server_metadata':{'dev':s.st_dev,'inode':s.st_ino,'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'bytes':s.st_size}}
        real_stat=Path.stat
        def proc_stat(p,*a,**k):return real_stat(binary) if p.name=='exe' else real_stat(p,*a,**k)
        with patch.object(Path,'stat',proc_stat):
            ns['verify_original_server'](plan,{'MainPID':'42'})
            binary.write_bytes(b'changed!')
            with self.assertRaises(RuntimeError):ns['verify_original_server'](plan,{'MainPID':'42'})

    def test_literal_and_packet_are_original_only(self):
        self.assertEqual(PACKET.CANDIDATE_SHA,'eed36d01de13f83a8abdc13e93c21883a3a48273da83fa1c813e65e4655babcf')
        self.assertEqual(PACKET.PATCH_SHA,'c553d631d18a01ce5511dec12e50a1a58817c92181d20f1443f17561f87a67ce')
        self.assertNotIn('io64_install_server',PACKET.ROOT_SOURCE)
        self.assertNotIn('os.replace(temporary,installed)',PACKET.ROOT_SOURCE)
        self.assertNotIn('rootfs_max_io_kib = 64',PACKET.ROOT_SOURCE)
        self.assertIn("report['rootfs256_memory256_verified']=len(bound)==8",PACKET.ROOT_SOURCE)
        main=__import__('inspect').getsource(PACKET.main)
        self.assertIn('cow4-original-256-recheck-node-a.pending.json',main)
        self.assertIn("restored.get('original_server_unchanged')",main)
        self.assertIn("restored.get('rootfs256_memory256_verified')",main)


if __name__=='__main__':unittest.main(verbosity=2)
