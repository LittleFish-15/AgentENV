import ast,importlib.util,sys,types,unittest
from pathlib import Path,PurePosixPath
H=Path(__file__).resolve().parent
if sys.platform=='win32':
    sys.modules.setdefault('fcntl',types.SimpleNamespace(LOCK_EX=2,LOCK_NB=4,flock=lambda *a:None))
    sys.modules.setdefault('pwd',types.SimpleNamespace())
s=importlib.util.spec_from_file_location('reconciliation',H/'Y_reconcile005.template.py');r=importlib.util.module_from_spec(s);s.loader.exec_module(r)
class Recovery(unittest.TestCase):
    def test_path_scope_does_not_match_prefix_neighbor(self):
        root=PurePosixPath('/data/jwk/aenv-y-20261107')
        self.assertTrue(r.under('/data/jwk/aenv-y-20261107/downloads',root))
        self.assertFalse(r.under('/data/jwk/aenv-y-20261107-other',root))
    def test_unrelated_process_not_selected(self):
        self.assertFalse(r.old_related({'args':['/usr/bin/curl'],'cwd':'/tmp','exe':'/usr/bin/curl'},'/exact/old/task.py'))
        self.assertTrue(r.old_related({'args':['python3','/exact/old/task.py'],'cwd':'/tmp','exe':'/usr/bin/python3'},'/exact/old/task.py'))
    def test_zombie_not_live(self):
        self.assertFalse(r.live(None));self.assertFalse(r.live({'status':'Z'}));self.assertTrue(r.live({'status':'S'}))
    def test_reconciliation_keeps_guard_and_old_evidence(self):
        text=(H/'Y_reconcile005.template.py').read_text(encoding='utf-8')
        self.assertIn('fcntl.LOCK_EX|fcntl.LOCK_NB',text);self.assertIn('os.pidfd_open',text)
        self.assertIn('state.before-reconciliation005.json',text)
        self.assertIn("'originalProcessExitCode':None",text)
        self.assertIn("'buildSucceeded':False",text)
        self.assertIn('controller_administrative_cancellation_not_original_wait_status',text)
        self.assertNotIn('.unlink(',text);self.assertNotIn('shutil.rmtree',text)
        self.assertNotIn('entry.write',text)
    def test_exact_original_source_no_patch(self):
        text=(H/'Y_original_build_v3.py').read_text(encoding='utf-8')
        for item in ('boostkit','5ca17126','initial-pool.patch',"['git','apply'",'startup_size'):self.assertNotIn(item,text)
        self.assertIn('ae9c62693839ce7effa2b45df31c0039ae4f9fbc',text)
        self.assertEqual(text.count('        verify_original_files()'),2)
    def test_rust_resume_and_supervisor_loss(self):
        text=(H/'Y_original_build_v3.py').read_text(encoding='utf-8')
        self.assertIn("'--continue-at','-'",text);self.assertIn("'--max-time','3600'",text)
        self.assertIn('seconds=4000',text);self.assertIn("reason='entry_supervisor_exited'",text)
        self.assertIn("sha(rust_archive.read_bytes())==rust['sha256']",text)
if __name__=='__main__':unittest.main()
