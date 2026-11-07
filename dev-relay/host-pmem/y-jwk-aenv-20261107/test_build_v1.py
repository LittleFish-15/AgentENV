import ast,importlib.util,json,os,sys,types,unittest
from pathlib import Path
H=Path(__file__).resolve().parent
if sys.platform=='win32':sys.modules.setdefault('pwd',types.SimpleNamespace(getpwnam=lambda name:None))
spec=importlib.util.spec_from_file_location('y_build',H/'Y_download_build_v1.py');b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
class Build(unittest.TestCase):
    def test_archive_digest_and_parts(self):
        m=b.DELIVERY['source_manifest'];raw=b''.join((H/p['name']).read_bytes() for p in m['parts'])
        self.assertEqual(b.sha(raw),m['archive_sha256']);self.assertEqual(len(raw),m['archive_bytes'])
        for p in m['parts']:self.assertEqual(b.sha((H/p['name']).read_bytes()),p['descriptor']['sha256'])
    def test_commit_object_identity(self):
        import hashlib
        raw=(H/'AgentENV-5ca17126.commit').read_bytes()
        self.assertEqual(hashlib.sha1(b'commit '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),b.DELIVERY['source_manifest']['commit'])
    def test_user_environment_scope(self):
        b.JWK=types.SimpleNamespace(pw_dir='/home/jwk')
        env=b.user_environment()
        self.assertEqual(env['HOME'],'/home/jwk');self.assertEqual(env['CARGO_BUILD_JOBS'],'4')
        self.assertEqual(env['CARGO_HTTP_SSL_VERIFY'],'false');self.assertEqual(env['GIT_CONFIG_VALUE_0'],'false')
        self.assertNotIn('GITHUB_TOKEN',env);self.assertNotIn('E2B_API_KEY',env)
    def test_no_runtime_actions(self):
        tree=ast.parse((H/'Y_download_build_v1.py').read_text())
        strings=[n.value for n in ast.walk(tree) if isinstance(n,ast.Constant) and isinstance(n.value,str)]
        self.assertNotIn('modprobe',strings);self.assertNotIn('systemctl',strings);self.assertNotIn('sysctl',strings)
        self.assertNotIn('swapoff',strings);self.assertNotIn('drop_caches',strings)
    def test_tls_downloads_and_digest_guards(self):
        source=(H/'Y_download_build_v1.py').read_text()
        self.assertEqual(source.count("['curl','-k','-fL'"),2)
        self.assertIn("sha(rust_archive.read_bytes())==rust['sha256']",source)
        self.assertIn("tree==manifest['tree']",source)
        self.assertIn("actual==manifest['commit']",source)
    def test_locked_build_and_all_binaries(self):
        source=(H/'Y_download_build_v1.py').read_text()
        self.assertIn("['cargo','build','--locked','--release','-j','4'",source)
        for name in ('server','aenv','uvm-ublk-daemon'):self.assertIn(name,source)
    def test_prior_state_and_memory_guards(self):
        source=(H/'Y_download_build_v1.py').read_text()
        self.assertIn("not (BASE/'build-status.json').exists()",source)
        self.assertIn('available_memory()<128*2**30',source)
        self.assertIn('now-START>10300',source)
        self.assertIn('os.killpg(proc.pid,signal.SIGKILL)',source)
if __name__=='__main__':unittest.main()
