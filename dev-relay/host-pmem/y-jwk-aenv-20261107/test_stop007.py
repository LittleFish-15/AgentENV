import ast,importlib.util,sys,types,unittest
from pathlib import Path
H=Path(__file__).resolve().parent
if sys.platform=='win32':sys.modules.setdefault('fcntl',types.SimpleNamespace())
s=importlib.util.spec_from_file_location('stop_dispatch',H/'Y_dispatch_stop007.py');d=importlib.util.module_from_spec(s);s.loader.exec_module(d)
class Stop(unittest.TestCase):
    def test_scope_boundary(self):
        self.assertTrue(d.within('/a/build/log','/a/build'));self.assertFalse(d.within('/a/build-other','/a/build'))
    def test_reader_not_a_cancellation_candidate(self):
        self.assertFalse(d.related({'exe':'/usr/bin/tail','cwd':'/','args':['tail','/a/build/log']},'/old/task.py','/a/build'))
    def test_stale_process_not_alive(self):self.assertFalse(d.alive(None));self.assertFalse(d.alive({'status':'Z'}))
    def test_cancel_is_bound_and_preserves_state(self):
        text=(H/'Y_dispatch_stop007.py').read_text(encoding='utf-8')
        for marker in ('os.pidfd_open','target[\'entry\'][\'sha256\']','Package transaction still active','state.before-stop007.json','originalProcessExitCode=None'):
            self.assertIn(marker,text)
        constants=[n.value for n in ast.walk(ast.parse(text)) if isinstance(n,ast.Constant) and isinstance(n.value,str)]
        self.assertNotIn('pkill',constants);self.assertNotIn('.unlink(',text)
    def test_checkout_is_original_no_patch_no_rust_download(self):
        text=(H/'Y_checkout_local008.py').read_text(encoding='utf-8')
        self.assertIn('ae9c62693839ce7effa2b45df31c0039ae4f9fbc',text)
        self.assertIn("'checkout','--detach',COMMIT",text)
        for forbidden in ('initial-pool.patch',"'apply'","'curl'",'rustup-init','--force','5ca17126'):self.assertNotIn(forbidden,text)
        self.assertIn("'CHECKOUT_COMPLETE_NO_LOCAL_RUST_1_91_1'",text)
if __name__=='__main__':unittest.main()
