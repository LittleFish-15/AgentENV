import ast
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('exporter',HERE/'AB_export_full_dax_service_bundle_v1.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)


class Checks(unittest.TestCase):
    def test_same_provider_contracts_are_reused(self):
        p=m.unpack()
        self.assertIn('host_pmem_rootfs.py',p['aenv_ub_provider'])
        self.assertIn('host_dax_worker.py',p['aenv_ub_provider'])
        for group in p.values():
            for name,source in group.items():
                self.assertEqual(Path(name).name,name)
                ast.parse(source,feature_version=(3,11))

    def test_altered_provider_payload_rejected(self):
        with patch.object(m,'PACKAGE_SHA','0'*64):
            with self.assertRaisesRegex(RuntimeError,'package differs'):m.unpack()

    def test_old_sdk_records_are_not_deletion_proof(self):
        name='aenv_'+'b'*32
        raw=('{"state":"serving","objects":[{"replica":{"objectName":"'+name+'"}}],'
             '"api_key":"do-not-export"}').encode()
        with patch.object(m.Path,'exists',return_value=True),patch.object(m,'read',return_value=raw):
            rows=m.old_objects('a')
        self.assertEqual(rows[0]['objectNames'],[name])
        self.assertNotIn('do-not-export',str(rows))
        self.assertIn('not SDK existence',rows[0]['meaning'])

    def test_export_has_no_device_sdk_execution_or_payload_copy(self):
        tree=ast.parse((HERE/'AB_export_full_dax_service_bundle_v1.py').read_text())
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):
                self.assertFalse(any(n.name in ('ctypes','subprocess','socket','shutil') for n in node.names))
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and \
               isinstance(node.func.value,ast.Name) and node.func.value.id=='os':
                self.assertNotIn(node.func.attr,('link','symlink','chmod','chown','system','popen'))


if __name__=='__main__':unittest.main()
