import ast, importlib.util, os, stat, sys, types, unittest, uuid
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).parent
if sys.platform == 'win32': sys.modules['fcntl'] = types.ModuleType('fcntl')
spec = importlib.util.spec_from_file_location('post_force_v2', HERE/'post_force_stage_body_v2.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class ControllerRead(unittest.TestCase):
    def setUp(self):
        # Windows lacks these Linux flags; this suite tests owner/content
        # contracts with real temporary file IO, not Linux open-flag behavior.
        self.flag_patches=[]
        for name in ('O_NOFOLLOW','O_NONBLOCK','O_CLOEXEC'):
            if not hasattr(os,name):
                change=patch.object(os,name,0,create=True);change.start();self.flag_patches.append(change)
        self.directory = (HERE/('owner-test-'+uuid.uuid4().hex)).resolve(); self.directory.mkdir()
        self.path = self.directory/'actual_guest_pair_continue_v2.py'
        self.raw = (HERE/'actual_guest_pair_continue_v2.py').read_bytes(); self.path.write_bytes(self.raw)
        self.root_patch = patch.object(m,'ROOT',self.directory); self.root_patch.start()
        self.actual_fstat = os.fstat

    def tearDown(self):
        self.root_patch.stop(); self.path.unlink(); self.directory.rmdir()
        for change in self.flag_patches:change.stop()

    def metadata(self, **changes):
        def invoke(fd):
            real = self.actual_fstat(fd)
            fields = {k:getattr(real,k) for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')}
            fields.update(st_uid=0,st_nlink=1,st_mode=stat.S_IFREG|0o600); fields.update(changes)
            return types.SimpleNamespace(**fields)
        return invoke

    def test_old_reader_reproduces_actual_root_owned_failure(self):
        tree=ast.parse((HERE/'AB_deploy_direct_deletefix_v2.py').read_text())
        definition=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='read')
        namespace={'Path':Path,'ROOT':self.directory,'os':os,'stat':stat,'need':m.need}
        exec(compile(ast.Module(body=[definition],type_ignores=[]),'<exact-old-reader>','exec'),namespace)
        with patch.object(os,'fstat',side_effect=self.metadata()):
            with self.assertRaisesRegex(RuntimeError,'Unexpected input owner/type/size'):
                namespace['read'](self.path)

    def test_root_owned_fixed_controller_reads_and_loads(self):
        with patch.object(os,'fstat',side_effect=self.metadata()):
            raw=m.root_controller_bytes(self.path)
        controller=m.load_code('controller_owner_regression',raw,
            '6c01a15e36a056b29a400e52f33f38981ff0abf3ca939185e6a4074dd9fda1fa',self.path)
        self.assertEqual(raw,self.raw); self.assertTrue(callable(controller.provider_status))

    def test_bad_metadata_rejected_with_file_name(self):
        for change in ({'st_uid':1204},{'st_uid':99},{'st_nlink':2},{'st_mode':stat.S_IFDIR|0o600},
                       {'st_mode':stat.S_IFREG|0o622},{'st_size':65537}):
            with self.subTest(change=change),patch.object(os,'fstat',side_effect=self.metadata(**change)):
                with self.assertRaisesRegex(RuntimeError,'actual_guest_pair_continue_v2.py'):
                    m.root_controller_bytes(self.path)

    def test_digest_tampering_rejected(self):
        self.path.write_bytes(self.raw.replace(b'ROOT=',b'root=',1))
        with patch.object(os,'fstat',side_effect=self.metadata()):
            with self.assertRaisesRegex(RuntimeError,'content digest differs'):m.root_controller_bytes(self.path)

    def test_metadata_change_during_read_rejected(self):
        calls=[]
        def changed(fd):
            value=self.metadata()(fd);calls.append(fd)
            if len(calls)==2:value.st_mtime_ns+=1
            return value
        with patch.object(os,'fstat',side_effect=changed):
            with self.assertRaisesRegex(RuntimeError,'changed during read'):m.root_controller_bytes(self.path)

    def test_wrong_path_rejected(self):
        with self.assertRaisesRegex(RuntimeError,'path changed'):m.root_controller_bytes(self.directory/'another.py')


if __name__=='__main__':
    spec=importlib.util.spec_from_file_location('old_decision_tests',HERE/'test_post_force_stage.py')
    old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
    old.m=m  # Run all existing drain/health decisions against the v2 body.
    suite=unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(ControllerRead),
                             unittest.defaultTestLoader.loadTestsFromTestCase(old.Decisions)])
    raise SystemExit(0 if unittest.TextTestRunner().run(suite).wasSuccessful() else 1)
