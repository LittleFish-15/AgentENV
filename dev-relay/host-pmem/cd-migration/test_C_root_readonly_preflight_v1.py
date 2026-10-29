import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import uuid
import sys
import types

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('preflight', HERE / 'C_root_readonly_preflight_v1.py')
m = importlib.util.module_from_spec(spec)
try:
    import grp
    spec.loader.exec_module(m)
except ModuleNotFoundError:
    fixture = types.SimpleNamespace(getgrgid=lambda gid: None)
    with patch.dict(sys.modules, {'grp': fixture}):
        spec.loader.exec_module(m)


class Tests(unittest.TestCase):
    def test_bounded_real_file_read_and_hash(self):
        root = HERE / ('rootread-test-' + uuid.uuid4().hex[:8]); root.mkdir(mode=0o755)
        path = (root / 'header').resolve(); path.write_bytes(b'struct example;')
        with patch.object(m.os, 'O_NOFOLLOW', 0, create=True), patch.object(m.os, 'O_NONBLOCK', 0, create=True):
            raw, facts = m.read_regular(path, 64)
            self.assertEqual(raw, b'struct example;')
            self.assertEqual(facts['sha256'], m.hashlib.sha256(raw).hexdigest())
            with self.assertRaisesRegex(RuntimeError, 'size exceeds'):
                m.read_regular(path, 2)

    def test_no_permission_or_service_mutation_in_inspect(self):
        from unittest.mock import MagicMock
        sdk = {'gid': 985, 'sha256': 'sdk'}
        def read(path, limit):
            if str(path).endswith('.ko'):
                return b'candidate', {'sha256': m.CANDIDATE_SHA}
            return b'header' if str(path).endswith('.h') else b'sdk', dict(sdk)
        with patch.object(m, 'read_regular', side_effect=read), patch.object(m, 'query', return_value={'exitCode': 1}), \
             patch.object(m.grp, 'getgrgid', return_value=MagicMock(gr_name='ubsmd')), \
             patch.object(m.os, 'chmod') as chmod, patch.object(m.os, 'chown', create=True) as chown:
            row = m.inspect()
            self.assertFalse(row['SDK_called']); self.assertFalse(row['kernelActionExecuted'])
            chmod.assert_not_called(); chown.assert_not_called()


if __name__ == '__main__':
    unittest.main()
