import ast
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('entry', HERE / 'C_prepare_and_switch_v1.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class Tests(unittest.TestCase):
    def test_embedded_sources_exact_and_python311(self):
        helper = m.unpack(m.BASE64_HELPER, m.HELPER_SHA)
        ast.parse(helper, feature_version=(3, 11))
        self.assertIn(b'validate_reference_snapshot', helper)
        adapter = m.unpack(m.BASE64_ADAPTER, m.ADAPTER_SHA)
        self.assertIn(b'#include <ubs_mem.h>', adapter)
        with self.assertRaises(RuntimeError):
            m.unpack(m.BASE64_ADAPTER, '0' * 64)

    def test_default_plan_makes_no_change(self):
        r = subprocess.run([sys.executable, '-I', '-B', str(HERE / 'C_prepare_and_switch_v1.py')],
                           capture_output=True, text=True, check=True)
        row = json.loads(r.stdout)
        self.assertEqual(row['logicalUbAllocationBytes'], 0)
        self.assertFalse(row['SDK_called']); self.assertFalse(row['defaultChanges'])

    def test_actual_reused_reference_guards(self):
        helper = types.ModuleType('helper')
        exec(compile(m.unpack(m.BASE64_HELPER, m.HELPER_SHA), '<helper>', 'exec'), helper.__dict__)
        helper.validate_reference_snapshot({'before':0,'after':0,'holders':[],'complete':True}, 123)
        for row in ({'before':2,'after':2,'holders':[],'complete':True},
                    {'before':0,'after':0,'holders':[],'complete':False}):
            with self.assertRaises(RuntimeError):
                helper.validate_reference_snapshot(row, 123)
        values = {'/sys/module/obmm/initstate':'live', '/sys/module/obmm/srcversion':'candidate',
                  '/sys/module/obmm/refcnt':'1'}
        with patch.object(helper, 'read', side_effect=lambda p: values[str(p)]), \
             patch.object(helper.Path, 'iterdir', return_value=iter([])), patch.object(helper, 'no_regions'), \
             patch.object(helper, 'command') as command:
            with self.assertRaises(RuntimeError):
                helper.Local({}).unload('candidate', {})
            command.assert_not_called()


if __name__ == '__main__':
    unittest.main()
