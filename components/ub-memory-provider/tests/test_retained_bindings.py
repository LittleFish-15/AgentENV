import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aenv_ub_provider import bindings


class RetainedBindingTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.gettempdir()).resolve() / ('native-archive-test-' + uuid.uuid4().hex)
        self.root.mkdir(mode=0o777)
        self.data = b'\0' * (2 * 1024**2)
        self.digest = 'sha256:' + hashlib.sha256(self.data).hexdigest()
        self.image = self.root/'base.img';self.image.write_bytes(self.data)
        self.source = self.root/'image.json'
        self.source.write_text(json.dumps({'lowers':[{'digest':'sha256:'+'f'*64,'size':4096}]}))
        self.runtime = {'verifier':'/opt/verifier','verifierSha256':'sha256:'+'a'*64,
                        'firecrackerSha256':'sha256:'+'b'*64,'verificationTimeoutSecs':60}

    def tearDown(self):
        assert self.root.resolve(strict=True)==self.root and self.root.parent==Path(tempfile.gettempdir()).resolve()
        shutil.rmtree(self.root)

    def bind(self, output, **kwargs):
        return bindings.rootfs(self.source, [self.image], '/run/provider.sock', len(self.data),
                               self.runtime, self.root/output, **kwargs)

    def test_opt_in_requires_v3_and_legacy_binding_stays_external(self):
        old = self.bind('legacy', snapshot_references=True)
        self.assertNotIn('snapshotSources',old)
        with self.assertRaises(ValueError):self.bind('bad',retain_snapshot_bases=True)
        new = self.bind('retained',snapshot_references=True,retain_snapshot_bases=True)
        self.assertEqual(new['snapshotSources'],[str(self.image.resolve())])
        with self.assertRaises(ValueError):
            bindings.relocate(self.root/'retained/binding.json','/run/peer.sock',self.runtime,self.root/'no-sources')
        relocated = bindings.relocate(self.root/'retained/binding.json','/run/peer.sock',self.runtime,
                                      self.root/'relocated',[self.image])
        self.assertEqual(relocated['layers'][0]['socket'],'/run/peer.sock')

    def manifest(self):
        directory=self.root/'native-pmem';directory.mkdir()
        path=directory/f'00-{self.digest[7:]}.img';path.write_bytes(self.data)
        manifest=self.root/'manifest.json'
        manifest.write_text(json.dumps({'nativeRootfs':{'version':1,'sourceImage':'sha256:'+'c'*64,
            'filesystem':'ext4','layers':[{'sha256':self.digest,'bytes':len(self.data)}],'archiveVersion':1}}))
        return manifest,path

    def test_repository_archive_reconstructs_portable_binding_without_sdk(self):
        manifest,_=self.manifest()
        value=bindings.retained_snapshot(manifest,self.root,'/run/new-generation.sock',len(self.data),
                                         self.runtime,self.root/'republish')
        self.assertEqual(value['layers'][0]['sha256'],self.digest)
        self.assertEqual(value['sourceImage'],'sha256:'+'c'*64)
        self.assertTrue((self.root/'republish/image-catalog.json').is_file())

    def test_corrupt_or_over_budget_archive_never_produces_binding(self):
        manifest,path=self.manifest()
        with self.assertRaises(ValueError):
            bindings.retained_snapshot(manifest,self.root,'/run/new.sock',1,self.runtime,self.root/'small')
        with path.open('r+b') as stream:stream.write(b'bad')
        with self.assertRaises(ValueError):
            bindings.retained_snapshot(manifest,self.root,'/run/new.sock',len(self.data),self.runtime,self.root/'bad')
        self.assertFalse((self.root/'bad').exists())

if __name__=='__main__':unittest.main()
