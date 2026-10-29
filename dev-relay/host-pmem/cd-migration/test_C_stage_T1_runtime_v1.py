import ast
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
import zlib

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('stage',HERE/'C_stage_T1_runtime_v1.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class Tests(unittest.TestCase):
    def test_package_exact_hash_and_python311_source(self):
        raw=zlib.decompress(base64.b64decode(m.PACKAGE,validate=True))
        self.assertEqual(hashlib.sha256(raw).hexdigest(),m.PACKAGE_SHA)
        package=json.loads(raw)
        self.assertIn('host_pmem_rootfs.py',package['aenv_ub_provider'])
        self.assertIn('host_dax_worker.py',package['aenv_ub_provider'])
        for group in package.values():
            for code in group.values():ast.parse(code,feature_version=(3,11))

    def test_toml_nested_config_preserves_paths_and_flags(self):
        value={'home_path':'/owned/root','snapshot':{'p2p_enabled':False,'repository_backend':'posix_fs'},
               'pool':{'block':{'enabled':True,'startup_prewarm':False}}}
        self.assertEqual(m.tomllib.loads(m.toml(value).decode()),value)

    def test_rootfs_host_read_path_no_guest_pmem_configuration(self):
        tree=ast.parse((HERE/'C_stage_T1_runtime_v1.py').read_bytes())
        strings={node.value for node in ast.walk(tree) if isinstance(node,ast.Constant) and isinstance(node.value,str) and len(node.value)<200}
        strings.update(node.arg for node in ast.walk(tree) if isinstance(node,ast.keyword))
        self.assertIn('ub_rootfs_index',strings)
        self.assertNotIn('native_pmem',strings)


if __name__=='__main__':unittest.main()
