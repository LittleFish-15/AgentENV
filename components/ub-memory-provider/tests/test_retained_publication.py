"""Real archive/config files and modeled SDK dispatch; no native allocation."""
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aenv_ub_provider import raw, retained, service


class RetainedPublicationTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.gettempdir()).resolve()/('nr-'+uuid.uuid4().hex[:10])
        self.root.mkdir(mode=0o777)
        data = b'\0'*(2*1024**2)
        self.digest = 'sha256:'+hashlib.sha256(data).hexdigest()
        (self.root/'native-pmem').mkdir(mode=0o777)
        self.image = self.root/'native-pmem'/('00-'+self.digest[7:]+'.img')
        self.image.write_bytes(data)
        self.manifest = self.root/'snapshot.json'
        self.manifest.write_text(json.dumps({'nativeRootfs':{'version':1,'sourceImage':'sha256:'+'c'*64,
            'filesystem':'ext4','layers':[{'sha256':self.digest,'bytes':len(data)}],'archiveVersion':1}}))
        self.adapter = self.root/'adapter.so';self.adapter.write_bytes(b'modeled SDK never loaded')
        self.adapter_sha = service.identity_bytes(self.adapter)
        self.runtime = {'verifier':'/opt/verifier','verifierSha256':'sha256:'+'a'*64,
                        'firecrackerSha256':'sha256:'+'b'*64,'verificationTimeoutSecs':60}
        self.out = self.root/'o'
        self.socket_patch = patch.object(retained,'data_socket',return_value='/run/new-native/data.sock')
        self.socket_patch.start()  # Linux socket spelling, Windows archive files.

    def tearDown(self):
        self.socket_patch.stop()
        assert self.root.resolve(strict=True).parent==Path(tempfile.gettempdir()).resolve() and self.root.name.startswith('nr-')
        shutil.rmtree(self.root)

    def publish(self,budget=4*1024**2):
        return retained.plan_publish(self.manifest,self.root,self.runtime,self.out,self.adapter,self.adapter_sha,
                                     'test',budget,128*1024**2,['peer'])

    def publication(self,mutate=None):
        plan=self.publish();spec=plan['binding']['layers'][0]
        manifest={'version':1,'ownerId':'d'*32,'mode':'pmem','readers':['peer'],
                  'replicas':[raw.shape(spec,'aenv_'+'e'*32)]}
        if mutate:mutate(manifest)
        path=self.root/'published.json';path.write_text(json.dumps(manifest))
        return path,service.identity_bytes(path),manifest

    def importer(self,path,pin,reader='peer'):
        return retained.plan_import(self.manifest,path,pin,reader,self.runtime,self.out,self.adapter,self.adapter_sha,
                                    'test',4*1024**2,128*1024**2)

    def test_default_plan_verifies_bytes_without_writing_or_opening_sdk(self):
        with patch.object(raw,'NativeRawBackend',side_effect=AssertionError('SDK forbidden')):
            plan=self.publish()
        self.assertFalse(self.out.exists());self.assertEqual(plan['alignedLogicalBytes'],4*1024**2)
        self.assertEqual(plan['binding']['snapshotSources'],[str(self.image)])
        self.assertEqual(plan['config']['role'],'publish')

    def test_alignment_corruption_and_existing_output_rejected_before_sdk(self):
        with self.assertRaisesRegex(ValueError,'Aligned'):self.publish(2*1024**2)
        with self.image.open('r+b') as stream:stream.write(b'corrupt')
        with self.assertRaises(ValueError):self.publish()
        self.assertFalse(self.out.exists())
        self.out.mkdir(mode=0o777)
        with self.assertRaisesRegex(ValueError,'new absolute'):self.publish()

    def test_import_exact_content_generation_and_reader_without_publisher_paths(self):
        path,pin,manifest=self.publication();plan=self.importer(path,pin)
        self.assertFalse(self.out.exists());self.assertEqual(plan['config']['role'],'import')
        self.assertEqual(plan['publisher'],manifest);self.assertNotIn('snapshotSources',plan['binding'])
        self.assertEqual(plan['binding']['layers'][0]['socket'],'/run/new-native/data.sock')
        self.assertEqual(plan['binding']['layers'][0]['sha256'],self.digest)

    def test_import_wrong_hash_reader_or_content_never_produces_output(self):
        path,pin,_=self.publication()
        with self.assertRaises(ValueError):self.importer(path,'sha256:'+'0'*64)
        with self.assertRaises(ValueError):self.importer(path,pin,'other')
        path,pin,_=self.publication(lambda m:m['replicas'][0]['identity'].update(sha256='sha256:'+'f'*64))
        with self.assertRaises(ValueError):self.importer(path,pin)
        self.assertFalse(self.out.exists())

    def test_execute_dispatches_standard_lifecycle_once_and_preserves_artifacts_on_failure(self):
        plan=self.publish();old_signal=retained.signal.getsignal(retained.signal.SIGTERM)
        try:
            with patch.object(service,'ordinary_linux'),patch.object(service,'inputs',return_value=(['verified'],None)),patch.object(service,'serve',side_effect=RuntimeError('modeled unresolved SDK result')) as serve:
                with self.assertRaisesRegex(RuntimeError,'unresolved'):retained.execute(plan)
                self.assertEqual(serve.call_count,1)
                self.assertEqual(serve.call_args.args[0]['role'],'publish')
            receipt=json.loads((self.out/'preparation.json').read_text())
            self.assertEqual(receipt['state'],'prepared_no_sdk')  # Only preparation, never the provider outcome.
            for name,pin in receipt['files'].items():self.assertEqual(service.identity_bytes(self.out/name),pin)
            self.assertEqual(json.loads((self.out/'execution.json').read_text())['state'],'provider_call_failed_preserve_journal')
            with patch.object(service,'ordinary_linux'),patch.object(service,'serve') as serve:
                with self.assertRaises(ValueError):retained.execute(plan)
                serve.assert_not_called()
        finally:retained.signal.signal(retained.signal.SIGTERM,old_signal)

    def test_execute_import_cannot_select_publisher_path(self):
        path,pin,manifest=self.publication();plan=self.importer(path,pin);old_signal=retained.signal.getsignal(retained.signal.SIGTERM)
        try:
            def finish(config,*unused):
                work=Path(config['workDir']);work.mkdir(mode=0o777)
                (work/'replicas.json').write_text(json.dumps(manifest))
                (work/'owner.json').write_text(json.dumps({'format':'native-raw-v1','state':'released','finalize_acknowledged':True,
                    'role':'import','mode':'pmem','ownerId':manifest['ownerId'],'manifestSha256':service.identity(manifest)}))
                (work/'release.json').write_text(json.dumps({'version':1,'ownerId':manifest['ownerId'],'readerId':'peer',
                    'manifestSha256':service.identity(manifest),'state':'released'}))
            with patch.object(service,'ordinary_linux'),patch.object(service,'inputs',return_value=(['verified'],manifest)),patch.object(service,'serve',side_effect=finish) as serve:
                retained.execute(plan)
                self.assertEqual(serve.call_args.args[0]['role'],'import')
                self.assertEqual(serve.call_args.args[2]['ownerId'],'d'*32)
            self.assertEqual(json.loads((self.out/'publisher.json').read_text()),manifest)
            self.assertEqual(json.loads((self.out/'execution.json').read_text())['state'],'provider_lifecycle_released')
        finally:retained.signal.signal(retained.signal.SIGTERM,old_signal)

    def test_cli_without_run_is_readonly(self):
        runtime=self.root/'runtime.json';runtime.write_text(json.dumps(self.runtime))
        args=['provider','publish-retained-snapshot','--manifest',str(self.manifest),'--artifact-root',str(self.root),
              '--device-runtime',str(runtime),'--output',str(self.out),'--adapter',str(self.adapter),
              '--adapter-sha256',self.adapter_sha,'--region','test','--max-bytes',str(4*1024**2),
              '--coverage-bytes',str(128*1024**2),'--reader','peer']
        output=io.StringIO()
        with patch.object(sys,'argv',args),patch.object(retained,'execute') as execute,contextlib.redirect_stdout(output):
            self.assertEqual(service.main(),0);execute.assert_not_called()
        self.assertFalse(self.out.exists());self.assertEqual(json.loads(output.getvalue())['state'],'retained_generation_validated_no_sdk')

    def test_return_without_release_journal_is_not_success(self):
        plan=self.publish();old_signal=retained.signal.getsignal(retained.signal.SIGTERM)
        try:
            with patch.object(service,'ordinary_linux'),patch.object(service,'inputs',return_value=(['verified'],None)),patch.object(service,'serve'):
                with self.assertRaises(FileNotFoundError):retained.execute(plan)
            result=json.loads((self.out/'execution.json').read_text())
            self.assertEqual(result['state'],'provider_call_failed_preserve_journal');self.assertFalse(result['retryPermitted'])
        finally:retained.signal.signal(retained.signal.SIGTERM,old_signal)

    def test_import_cli_validates_without_sdk_or_copying_archive_bytes(self):
        path,pin,_=self.publication();runtime=self.root/'runtime.json';runtime.write_text(json.dumps(self.runtime))
        self.image.unlink()  # Import needs portable identity; Runtime hydrates archives separately.
        args=['provider','import-retained-snapshot','--manifest',str(self.manifest),'--publisher-manifest',str(path),
              '--publisher-manifest-sha256',pin,'--reader','peer','--device-runtime',str(runtime),
              '--output',str(self.out),'--adapter',str(self.adapter),'--adapter-sha256',self.adapter_sha,
              '--region','test','--max-bytes',str(4*1024**2),'--coverage-bytes',str(128*1024**2)]
        with patch.object(sys,'argv',args),patch.object(retained,'execute') as execute,contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(service.main(),0);execute.assert_not_called()
        self.assertFalse(self.out.exists())


if __name__=='__main__':unittest.main()
