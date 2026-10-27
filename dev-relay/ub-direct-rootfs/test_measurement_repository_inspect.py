import hashlib,importlib.util,json,unittest
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('inspect_repo',Path(__file__).with_name('AB_inspect_measurement_repository_v1.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class MetadataOnly(unittest.TestCase):
    def test_reports_metadata_without_reading_layers(self):
        raw=json.dumps({'id':m.SID,'resources':{'cpu_count':2,'memory_mib':4096,'disk_size_mib':10240},
                        'committed':{'rootfs_layers':[{}]*8,'memory_layers':[{}]}}).encode()
        with patch.object(m,'small',return_value=raw) as read:
            value=m.record(Path('/home/jwk/agent/repository'))
        self.assertEqual(value['sha256'],hashlib.sha256(raw).hexdigest())
        self.assertEqual(value['rootfsLayerCount'],8)
        self.assertEqual(read.call_count,1)
        self.assertEqual(read.call_args.args[0].name,m.SID+'.json')
    def test_missing_record_not_success(self):
        with patch.object(m,'small',side_effect=FileNotFoundError()),patch.object(Path,'is_dir',return_value=True):
            value=m.record(Path('/home/jwk/agent/repository'))
        self.assertIs(value['present'],False)
    def test_runtime_mount_view_is_labelled(self):
        with patch.object(m,'small',return_value=b'{}') as read:m.record(Path('/home/jwk/agent/repository'),1234)
        self.assertIn('1234/root',read.call_args.args[0].as_posix())
    def test_invalid_metadata_kept_as_error(self):
        with patch.object(m,'small',side_effect=ValueError('changed')):value=m.record(Path('/home/jwk/agent/repository'))
        self.assertEqual(value['errorType'],'ValueError');self.assertNotIn('present',value)
if __name__=='__main__':unittest.main()
