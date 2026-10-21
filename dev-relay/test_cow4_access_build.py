import ast,copy,hashlib,importlib.util,os,shutil,unittest,uuid
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('access_build_packet',HERE/'cow4_access_build.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class BuildPacket(unittest.TestCase):
    def setUp(self):
        self.path=Path.cwd()/('.access-build-test-'+uuid.uuid4().hex);self.path.mkdir(mode=0o755)
    def tearDown(self):
        self.assertEqual(self.path.resolve().parent,Path.cwd().resolve());self.assertTrue(self.path.name.startswith('.access-build-test-'))
        shutil.rmtree(self.path)
    def test_archive_and_all_patch_preimages_match_original(self):
        m.unpack(self.path)
        self.assertEqual(hashlib.sha256((self.path/'Cargo.lock').read_bytes()).hexdigest(),m.LOCK_SHA)
        for name,v in m.PATCH_FILES.items():self.assertEqual(hashlib.sha256((self.path/name).read_bytes()).hexdigest(),v['after_sha256'])
        self.assertFalse((self.path/'AGENTS.md').exists())
        self.assertTrue((self.path/'CLAUDE.md').is_file())
        self.assertIn('with_read_source', (self.path/'storage/ublk/src/impls/overlaybd_target.rs').read_text(encoding='utf-8'))
        self.assertIn('rootfs_access_trace::record', (self.path/'storage/overlaybd/src/backend/local.rs').read_text(encoding='utf-8'))
    def test_tampered_manifest_stops_before_extraction(self):
        changed=copy.deepcopy(m.PATCH_FILES);next(iter(changed.values()))['after_sha256']='0'*64
        with patch.object(m,'PATCH_FILES',changed),self.assertRaises(RuntimeError):m.unpack(self.path)
        self.assertFalse(list(self.path.iterdir()))
    def test_only_observation_source_delta(self):
        self.assertEqual(m.BASE_COMMIT,'ae9c62693839ce7effa2b45df31c0039ae4f9fbc')
        self.assertEqual(len(m.PATCH_FILES),7)
        self.assertIn('storage/overlaybd/examples/rootfs_access_calibration.rs',m.PATCH_FILES)
        self.assertNotIn('src/cfg.rs',m.PATCH_FILES)
        self.assertNotIn('Cargo.lock',m.PATCH_FILES)
        self.assertNotIn('storage/ublk-daemon/src/protocol.rs',m.PATCH_FILES)
    def test_build_has_no_service_or_kernel_commands(self):
        t=ast.parse((HERE/'rootfs-access/build_runtime.py').read_text(encoding='utf-8'))
        strings=[n.value for n in ast.walk(t) if isinstance(n,ast.Constant) and isinstance(n.value,str)]
        for forbidden in ('systemctl','modprobe','rmmod','sudo','--allow-locked-network'):self.assertNotIn(forbidden,strings)
        self.assertIn('--frozen',strings);self.assertIn('uvm-ublk-daemon',strings)
        self.assertIn('rootfs_access_trace::',strings)

if __name__=='__main__':unittest.main()
