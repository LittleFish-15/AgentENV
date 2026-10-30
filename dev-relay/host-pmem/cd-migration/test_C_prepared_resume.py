import ast
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
HERE=Path(__file__).resolve().parent
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
r=load('resume',HERE/'C_run_maintenance_v12.py')

# Execute the real guard-replacement/reuse code against an existing config,
# without a Linux environment or writes to any real service input.
def prepare_sources():
    config=WORK/'existing-config.json'
    need(not config.exists(),'Unreviewed dependency config preserved')
    write(config,b'expected config',1204,1205)

class Tests(unittest.TestCase):
    def module(self):
        m=load('old_fixed',HERE/'C_run_maintenance_v9.py')
        m.load_baseline=Mock();m.folder=Mock();m.write=Mock();self.original_write=m.write
        m.prepare_sources=prepare_sources
        return r.configure_continuation(m,Mock(),{'protectedDevices':{}},982)
    def metadata(self,uid=1204,gid=1205,mode=0o100600):return SimpleNamespace(st_uid=uid,st_gid=gid,st_mode=mode)
    def test_identical_preexisting_config_is_reused_without_write(self):
        m=self.module()
        with patch.object(Path,'exists',return_value=True),patch.object(Path,'is_symlink',return_value=False),patch.object(Path,'resolve',lambda p:p),patch.object(Path,'stat',return_value=self.metadata()),patch.object(Path,'read_bytes',return_value=b'expected config'):
            m.prepare_sources()
        self.original_write.assert_not_called()
    def test_changed_preexisting_config_is_not_overwritten(self):
        m=self.module()
        with patch.object(Path,'exists',return_value=True),patch.object(Path,'is_symlink',return_value=False),patch.object(Path,'resolve',lambda p:p),patch.object(Path,'stat',return_value=self.metadata()),patch.object(Path,'read_bytes',return_value=b'foreign config'):
            with self.assertRaisesRegex(RuntimeError,'file differs'):m.prepare_sources()
        self.original_write.assert_not_called()
    def test_changed_existing_root_source_is_not_overwritten(self):
        m=self.module()
        with patch.object(Path,'exists',return_value=True),patch.object(Path,'resolve',lambda p:p),patch.object(Path,'stat',return_value=self.metadata(0,0,0o100644)),patch.object(Path,'read_bytes',return_value=b'changed source'):
            with self.assertRaisesRegex(RuntimeError,'file differs'):m.write(r.NEW/'code/source.py',b'expected source',mode=0o644)
        self.original_write.assert_not_called()
    def test_resume_never_calls_device_delete_or_group_creation(self):
        tree=ast.parse((HERE/'C_run_maintenance_v12.py').read_text())
        main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main')
        direct={n.func.id for n in ast.walk(main) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name)}
        self.assertFalse(direct & {'normal_recovery','reserve_group'})
        source=ast.get_source_segment((HERE/'C_run_maintenance_v12.py').read_text(),main)
        for gate in ("prepared['unknownCreate'] is False","prepared['SDK_called'] is False","prepared['units']=={}","resume-v12-before.json"):
            self.assertIn(gate,source)

if __name__=='__main__':unittest.main()
