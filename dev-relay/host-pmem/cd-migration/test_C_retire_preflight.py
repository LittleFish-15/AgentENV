import ast
from pathlib import Path
import unittest
HERE=Path(__file__).resolve().parent


class Tests(unittest.TestCase):
    def test_no_stop_delete_signal_or_device_io(self):
        source=ast.parse((HERE/'C_run_maintenance_v7.py').read_bytes(),feature_version=(3,11))
        function=next(x for x in source.body if isinstance(x,ast.FunctionDef) and x.name=='retirement_prerequisites')
        calls={getattr(node.func,'attr','') for node in ast.walk(function) if isinstance(node,ast.Call)}
        self.assertFalse(calls & {'kill','ioctl','connect','send','sendall','unlink','chmod','chown','Popen','run','write'})
    def test_arguments_are_allowlisted_not_raw_uploaded(self):
        source=(HERE/'C_run_maintenance_v7.py').read_text()
        self.assertIn("'selectedPathArguments':selected",source)
        self.assertNotIn("'argv':argv",source)
        self.assertNotIn("'cmdline':",source)


if __name__=='__main__':unittest.main()
