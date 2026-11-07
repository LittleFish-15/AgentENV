import ast,importlib.util,json,os,sys,tarfile,types,unittest
from pathlib import Path
H=Path(__file__).resolve().parent
if sys.platform=='win32':sys.modules.setdefault('pwd',types.SimpleNamespace(getpwnam=lambda name:None))
s=importlib.util.spec_from_file_location('original_y_build',H/'Y_original_build_v2.py');b=importlib.util.module_from_spec(s);s.loader.exec_module(b)
class Original(unittest.TestCase):
    def test_exact_X_delivery_digest(self):
        m=b.DELIVERY['source_manifest'];raw=b''.join((H/p['name']).read_bytes() for p in m['parts'])
        self.assertEqual(b.sha(raw),'ca0c5e713b423c60b25e24187663fcba945721cc603d497b962168c124a35748')
        self.assertEqual(len(raw),2302583)
        import io
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as t:
            self.assertEqual(t.pax_headers['comment'],'ae9c62693839ce7effa2b45df31c0039ae4f9fbc')
            self.assertEqual(sum(m.isfile() for m in t.getmembers()),802)
            self.assertEqual(sum(m.issym() for m in t.getmembers()),1)
    def test_no_patch_or_substitute_source(self):
        source=(H/'Y_original_build_v2.py').read_text(encoding='utf-8')
        for text in ('boostkit','5ca17126','initial-pool.patch',"['git','apply'",'request_startup_fill','startup_size'):
            self.assertNotIn(text,source)
        self.assertNotIn('startup_patch',b.DELIVERY)
        self.assertEqual(b.STATE['source_commit'],'ae9c62693839ce7effa2b45df31c0039ae4f9fbc')
    def test_all_original_files_checked_twice(self):
        source=(H/'Y_original_build_v2.py').read_text(encoding='utf-8')
        self.assertEqual(source.count('        verify_original_files()'),2)
        self.assertIn("original_source_unchanged_after_build",source)
        self.assertIn("path.is_symlink() and os.readlink(path)==expected['target']",source)
    def test_separate_build_directory(self):
        self.assertEqual(str(b.BASE).replace('\\','/'),'/data/jwk/aenv-y-ae9c626-20261107')
        self.assertEqual(str(b.SOURCE).replace('\\','/'),'/data/jwk/aenv-y-ae9c626-20261107/source/original-ae9c626')
    def test_user_environment_and_network_mode(self):
        b.JWK=types.SimpleNamespace(pw_dir='/home/jwk');env=b.user_environment()
        self.assertEqual(env['USER'],'jwk');self.assertEqual(env['CARGO_BUILD_JOBS'],'4')
        self.assertEqual(env['CARGO_HTTP_SSL_VERIFY'],'false');self.assertNotIn('E2B_API_KEY',env)
        source=(H/'Y_original_build_v2.py').read_text(encoding='utf-8')
        self.assertEqual(source.count("['curl','-k','-fL'"),2)
    def test_no_runtime_or_host_tuning_actions(self):
        t=ast.parse((H/'Y_original_build_v2.py').read_text(encoding='utf-8'))
        strings=[n.value for n in ast.walk(t) if isinstance(n,ast.Constant) and isinstance(n.value,str)]
        for item in ('systemctl','modprobe','sysctl','swapoff','drop_caches'):self.assertNotIn(item,strings)
    def test_locked_native_build_and_guards(self):
        source=(H/'Y_original_build_v2.py').read_text(encoding='utf-8')
        self.assertIn("['cargo','build','--locked','--release','-j','4'",source)
        self.assertIn("not (BASE/'build-status.json').exists()",source)
        self.assertIn('available_memory()<128*2**30',source)
        self.assertIn('os.killpg(proc.pid,signal.SIGKILL)',source)
if __name__=='__main__':unittest.main()
