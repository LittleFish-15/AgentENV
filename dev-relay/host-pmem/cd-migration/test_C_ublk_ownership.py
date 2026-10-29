import ast
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('diag',HERE/'C_run_maintenance_v5.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class Tests(unittest.TestCase):
    def test_device_inventory_uses_metadata_only(self):
        p=Mock();p.lstat.return_value=SimpleNamespace(st_uid=0,st_gid=0,st_mode=0o20600,st_ino=10,st_rdev=99)
        p.is_symlink.return_value=False
        row=m.device_metadata(p)
        self.assertEqual(row['rdev'],99);p.open.assert_not_called();p.read_bytes.assert_not_called()

    def test_snapshot_no_mutation_or_device_data_open(self):
        source=ast.parse((HERE/'C_run_maintenance_v5.py').read_bytes())
        function=next(x for x in source.body if isinstance(x,ast.FunctionDef) and x.name=='snapshot')
        calls={getattr(node.func,'attr','') for node in ast.walk(function) if isinstance(node,ast.Call)}
        self.assertFalse(calls & {'chmod','chown','unlink','remove','run','Popen','kill','ioctl','write','write_bytes','write_text'})
        literal_modes=[node.args[0].value for node in ast.walk(function) if isinstance(node,ast.Call)
            and getattr(node.func,'attr','')=='open' and node.args and isinstance(node.args[0],ast.Constant)]
        self.assertEqual(literal_modes,['rb'])


if __name__=='__main__':unittest.main()
