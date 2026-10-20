import base64
import importlib.util
import json
import os
from pathlib import Path
import shutil
import unittest
import uuid
from unittest import mock

spec=importlib.util.spec_from_file_location('cross_prepare',Path(__file__).with_name('ub_cross_prepare.py'))
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)

class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.root=Path.cwd()/('.ub-cross-test-'+uuid.uuid4().hex)
        self.root.mkdir();self.root=self.root.resolve()
        # Windows 0700 ACLs exclude the sandbox test identity. Only this local
        # test fixture uses inherited directory ACLs; production stays 0700.
        real_mkdir=os.mkdir
        self.mkdir_patch=mock.patch.object(os,'mkdir',side_effect=lambda path,mode=0o777,**kw:real_mkdir(path,0o755 if os.name=='nt' else mode,**kw))
        self.mkdir_patch.start()
        self.patches=[mock.patch.object(c,'ROOT',self.root),mock.patch.object(c,'MOD',self.root/'modified')]
        for p in self.patches:p.start()
        layers=[{'digest':'sha256:'+format(i,'064x'),'size':1} for i in range(16)]
        layers[-1]['size']=1526478848-15
        record={'id':c.SNAPSHOT,'resources':{'cpu_count':1,'memory_mib':512},
                'committed':{'memory_layers':layers[:2],'rootfs_layers':[{'Managed':v} for v in layers[2:]]}}
        self.catalog=json.dumps(record).encode()
        self.pin=mock.patch.object(c,'CATALOG_SHA',c.sha(self.catalog));self.pin.start()
        raw={c.FILES[0]:self.catalog,c.FILES[1]:b'opaque VM state; never execute',c.FILES[2]:b'{}',c.FILES[3]:b'committed'}
        self.package={'revision':'ub-cross-template-input-v1','snapshot_id':c.SNAPSHOT,'catalog_sha256':c.CATALOG_SHA,
          'marker_seed':c.SEED,'layers':c.layer_inventory(self.catalog),
          'dependencies':{k:{'bytes':1,'sha256':'a'*64} for k in c.DEPS},
          'files':{k:{'base64':base64.b64encode(v).decode(),'sha256':c.sha(v),'bytes':len(v)} for k,v in raw.items()}}
    def tearDown(self):
        self.pin.stop()
        for p in reversed(self.patches):p.stop()
        self.mkdir_patch.stop()
        self.assertEqual(self.root.parent,Path.cwd().resolve())
        self.assertTrue(self.root.name.startswith('.ub-cross-test-'))
        shutil.rmtree(self.root)
    def test_exact_metadata_no_layer_payload(self):
        decoded,layers=c.validate_package(self.package)
        self.assertEqual(set(decoded),set(c.FILES));self.assertEqual(len(layers),16)
        self.assertFalse(any(k.startswith('managed-layers/') for k in decoded))
    def test_path_injection_rejected(self):
        self.package['files']['../../outside']={'base64':'','sha256':c.sha(b''),'bytes':0}
        with self.assertRaisesRegex(RuntimeError,'selector'):c.validate_package(self.package)
    def test_tampered_content_rejected(self):
        self.package['files'][c.FILES[1]]['base64']=base64.b64encode(b'changed').decode()
        with self.assertRaisesRegex(RuntimeError,'checksum'):c.validate_package(self.package)
    def test_wrong_catalog_identity_rejected(self):
        self.package['catalog_sha256']='0'*64
        with self.assertRaisesRegex(RuntimeError,'Unexpected package'):c.validate_package(self.package)
    def test_missing_commit_rejected(self):
        value=b'pending';self.package['files'][c.FILES[3]]={'base64':base64.b64encode(value).decode(),'sha256':c.sha(value),'bytes':len(value)}
        with self.assertRaisesRegex(RuntimeError,'commit marker'):c.validate_package(self.package)
    def test_existing_conflict_preserved(self):
        p=self.root/'preserved';p.write_bytes(b'old')
        with mock.patch.object(c,'read',side_effect=lambda p,*a:p.read_bytes()):
            with self.assertRaisesRegex(RuntimeError,'preserved'):c.put(p,b'new')
        self.assertEqual(p.read_bytes(),b'old')
    def test_staging_idempotent_and_not_registered(self):
        raw=c.encoded(self.package);incoming=self.root/'input.json';incoming.write_bytes(raw)
        with mock.patch.object(c,'read',side_effect=lambda p,*a:p.read_bytes()),mock.patch.object(c,'deployment',return_value={'issues':[]}),mock.patch.object(c,'fingerprint',return_value={'bytes':1,'sha256':'a'*64}):
            report={};c.stage_b(self.root,report,incoming)
            c.stage_b(self.root,{},incoming)
        self.assertEqual(report['layer_payload_bytes_copied'],0)
        self.assertFalse(report['registered_in_live_repository'])
        self.assertFalse((c.MOD/'state').exists())
        self.assertTrue((Path(report['staged_directory'])/c.FILES[1]).is_file())
    def test_dependency_mismatch_stops_before_stage(self):
        incoming=self.root/'input.json';incoming.write_bytes(c.encoded(self.package))
        with mock.patch.object(c,'read',side_effect=lambda p,*a:p.read_bytes()),mock.patch.object(c,'deployment',return_value={'issues':[]}),mock.patch.object(c,'fingerprint',return_value={'bytes':1,'sha256':'b'*64}):
            with self.assertRaisesRegex(RuntimeError,'dependency mismatch'):c.stage_b(self.root,{},incoming)
        self.assertFalse((self.root/'relay/ub-cross-input').exists())
    def test_symlink_redirect_rejected(self):
        with mock.patch.object(Path,'resolve',return_value=self.root/'different'):
            with self.assertRaisesRegex(RuntimeError,'Redirected'):c.safe(self.root/'input')
    def test_budget_rejected_before_decode(self):
        self.package['files'][c.FILES[1]]['bytes']=c.MAX_METADATA+1
        with self.assertRaisesRegex(RuntimeError,'descriptor'):c.validate_package(self.package)

if __name__=='__main__':unittest.main()
