import ast,importlib.util,sys,types,unittest
from pathlib import Path
H=Path(__file__).resolve().parent
if sys.platform=='win32':sys.modules.setdefault('pwd',types.SimpleNamespace());sys.modules.setdefault('fcntl',types.SimpleNamespace())
s=importlib.util.spec_from_file_location('reuse',H/'Y_reuse_compile010.py');b=importlib.util.module_from_spec(s);s.loader.exec_module(b)
class Reuse(unittest.TestCase):
    def test_expected_commit_and_private_destination(self):
        self.assertEqual(b.COMMIT,'ae9c62693839ce7effa2b45df31c0039ae4f9fbc')
        self.assertEqual(str(b.BASE).replace('\\','/'),'/home/jwk/aenv-y-20261109')
        self.assertEqual(b.STATE['source_patches'],[])
    def test_no_global_changes_or_rust_download(self):
        source=(H/'Y_reuse_compile010.py').read_text(encoding='utf-8');tree=ast.parse(source)
        values=[n.value for n in ast.walk(tree) if isinstance(n,ast.Constant) and isinstance(n.value,str)]
        for cmd in ('dnf','apt','apt-get','systemctl','modprobe','sysctl','curl','rustup-init','apply'):self.assertNotIn(cmd,values)
        self.assertNotIn('initial-pool.patch',source);self.assertNotIn('5ca17126',source)
    def test_original_repository_not_checked_out_or_mutated(self):
        source=(H/'Y_reuse_compile010.py').read_text(encoding='utf-8')
        self.assertIn("'--local','--no-hardlinks','--no-checkout'",source)
        self.assertIn("str(SOURCE),'checkout','--detach',COMMIT",source)
        self.assertIn("'--no-optional-locks'",source)
    def test_credential_copy_is_excluded(self):
        source=(H/'Y_reuse_compile010.py').read_text(encoding='utf-8')
        self.assertIn("for name in ('objects','refs','HEAD','packed-refs','shallow')",source)
        tree=ast.parse(source)
        copies=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='copy_component']
        for call in copies:
            text=ast.unparse(call)
            for field in ('credentials.toml','id_rsa','id_ed25519'):self.assertNotIn(field,text)
    def test_copy_operation_does_not_hardlink(self):
        source=(H/'Y_reuse_compile010.py').read_text(encoding='utf-8')
        self.assertNotIn('os.link(',source);self.assertIn('shutil.copytree(source,dest,symlinks=True)',source)
        self.assertIn("path.resolve().is_relative_to(BASE)",source)
    def test_build_resource_and_integrity_guards(self):
        source=(H/'Y_reuse_compile010.py').read_text(encoding='utf-8')
        for value in ('available<128*2**30','os.getppid()!=PARENT',"'--locked','--release','-j','4'",'os.killpg(p.pid,signal.SIGKILL)',"sha_file(SOURCE/'Cargo.lock')==STATE['lockfile_sha256']"):
            self.assertIn(value,source)
if __name__=='__main__':unittest.main()
