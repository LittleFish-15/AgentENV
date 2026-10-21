import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class PortableContracts(unittest.TestCase):
    def test_report_requires_explicit_evidence_and_does_not_invent_data(self):
        run = subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'report.py'),
                              '--output', 'unused-new-report'], capture_output=True, text=True)
        self.assertEqual(run.returncode, 2)
        self.assertIn('--evidence', run.stderr)
        report = load('report')
        text, intersections = report.render({'version': 1}, [])
        self.assertIn('Net physical saving: NA', text)
        self.assertEqual(intersections, [])

    def test_unknown_or_injectable_guest_filesystem_paths_are_refused(self):
        tools = load('prepare_guest_tools')
        for path in ['/tmp/a\nrm /init', '/tmp/a"b', '/tmp/a/../b', 'relative']:
            with self.subTest(path=path), self.assertRaises(ValueError):
                tools.debugfs_token(path)

    def test_guest_handoff_rejects_unknown_fields_or_unbounded_mapping(self):
        guest = load('native_pmem_guest')
        spec = {'objectId': 'fixture', 'generation': 'fixture-generation',
                'sha256': 'sha256:' + 'a' * 64, 'bytes': 2 * 1024 * 1024,
                'socket': '/tmp/example-generation/data.sock'}
        self.assertEqual(guest.validate_spec(spec), spec)
        for update in [{'bytes': True}, {'bytes': 3}, {'socket': 'relative'}]:
            with self.assertRaises(ValueError):
                guest.validate_spec(dict(spec, **update))
        with self.assertRaises(ValueError):
            guest.validate_spec(dict(spec, privateCow=True))

    def test_mapping_observation_is_not_claimed_as_guest_cow(self):
        probe = load('owned_mapping_probe')
        self.assertFalse(probe.isolated({}))
        self.assertIn('MAP_PRIVATE', probe.SOURCE)
        self.assertIn('base_after_', probe.SOURCE)
        self.assertIn('children_safe', probe.SOURCE)


if __name__ == '__main__':
    unittest.main()
