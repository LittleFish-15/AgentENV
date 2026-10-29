import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
import zlib

spec = importlib.util.spec_from_file_location('collector', Path(__file__).with_name('C_collect_root_preflight_v1.py'))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class Tests(unittest.TestCase):
    def setUp(self):
        self.expected = {'machineId': 'machine', 'bootId': 'boot', 'kernel': 'kernel'}
        header = b'struct ABI {int value;};'
        self.row = dict(self.expected, status='C_ROOT_COMPATIBILITY_INSPECTED_NO_SDK_OR_KERNEL_ACTION',
            header={'contentBase64': base64.b64encode(header).decode(), 'sha256': hashlib.sha256(header).hexdigest()},
            SDK_called=False, Guest_created=False, moduleChanged=False, servicesChanged=False,
            permissionsChanged=False, kernelActionExecuted=False)

    def test_private_report_lossless_roundtrip(self):
        raw = json.dumps(self.row).encode()
        result = m.pack(raw, self.row, self.expected)
        self.assertEqual(zlib.decompress(base64.b64decode(result['privateReport'])), raw)
        self.assertEqual(result['reportSha256'], hashlib.sha256(raw).hexdigest())

    def test_other_boot_refused(self):
        self.row['bootId'] = 'other'
        with self.assertRaisesRegex(RuntimeError, 'another machine'):
            m.pack(b'{}', self.row, self.expected)

    def test_header_tamper_refused(self):
        self.row['header']['sha256'] = '0' * 64
        with self.assertRaisesRegex(RuntimeError, 'header receipt SHA'):
            m.pack(b'{}', self.row, self.expected)


if __name__ == '__main__':
    unittest.main()
