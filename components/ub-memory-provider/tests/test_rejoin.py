"""Read-only rejoin contracts; no SDK, module or remote liveness acceptance."""
import copy
import hashlib
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aenv_ub_provider import contract, rejoin, service
import test_control_lifecycle as lifecycle


class RejoinTests(unittest.TestCase):
    def setUp(self):
        self.manifest = {'version':1, 'ownerId':'a'*32, 'mode':'pmem', 'readers':['retained-b'],
            'replicas':[{'objectName':'aenv_'+'b'*32, 'mappingBytes':4*1024**2,
                'identity':{'objectId':'fixture','generation':'c'*32,'sha256':'sha256:'+'d'*64,'bytes':4*1024**2}}]}
        self.config = {'version':1, 'role':'rejoin', 'mode':'pmem', 'workDir':'/new-a',
            'adapter':'/adapter.so','adapterSha256':'sha256:'+'e'*64,'region':'default',
            'logicalBudgetBytes':4*1024**2,'maxCoverageBytes':8*1024**2,
            'readerId':'rejoined-a','manifest':'/original-manifest.json',
            'rejoinPermit':'/home/jwk/root/public/permit.json','rejoinPermitSha256':'sha256:'+'f'*64}
        self.permit = {'version':1,'scope':'readonly-native-publication-rejoin','machineId':'1'*32,
            'previousPublisherBootId':'00000000-0000-0000-0000-000000000001',
            'currentBootId':'00000000-0000-0000-0000-000000000002','readerId':'rejoined-a',
            'ownerId':self.manifest['ownerId'],'manifestSha256':service.identity(self.manifest),
            'logicalBytes':4*1024**2,'releaseAuthority':'local-mappings-only',
            'retainedPeer':{'machineId':'2'*32,'bootId':'00000000-0000-0000-0000-000000000003',
                            'readerId':'retained-b','pid':234,'startTicks':'567'}}

    def validate(self, permit=None, manifest=None):
        with patch.object(rejoin,'read_permit',return_value=self.permit if permit is None else permit), \
             patch.object(rejoin,'local_identity',return_value=('1'*32,self.permit['currentBootId'])):
            return rejoin.validate_permit(self.config,self.manifest if manifest is None else manifest)

    def test_valid_rejoin_preserves_old_publication(self):
        before = copy.deepcopy(self.manifest)
        self.validate()
        self.assertEqual(before,self.manifest)
        self.assertNotIn(self.config['readerId'],self.manifest['readers'])

    def test_generation_boot_machine_and_authority_are_bound(self):
        cases = {'scope':'import-any-object','machineId':'3'*32,'ownerId':'0'*32,
                 'manifestSha256':'sha256:'+'0'*64,'logicalBytes':8*1024**2,
                 'releaseAuthority':'delete-object','readerId':'different-reader',
                 'previousPublisherBootId':self.permit['currentBootId'],'currentBootId':'bad'}
        for key,value in cases.items():
            with self.subTest(key=key):
                p=copy.deepcopy(self.permit);p[key]=value
                with self.assertRaises(ValueError):self.validate(p)

    def test_existing_reader_identity_cannot_be_impersonated(self):
        self.config['readerId']='retained-b';self.permit['readerId']='retained-b'
        with self.assertRaises(ValueError):self.validate()

    def test_changed_retained_peer_is_rejected(self):
        for key,value in [('readerId','other'),('machineId','1'*32),('pid',0),('startTicks','unknown')]:
            with self.subTest(key=key):
                p=copy.deepcopy(self.permit);p['retainedPeer'][key]=value
                with self.assertRaises(ValueError):self.validate(p)

    def test_manifest_inputs_uses_exact_permit_without_allocating(self):
        before=copy.deepcopy(self.manifest)
        with patch.object(service,'read_json',return_value=self.manifest), \
             patch.object(rejoin,'validate_permit',return_value=self.permit) as validate:
            self.assertEqual(service.manifest_inputs(self.config),self.manifest)
            validate.assert_called_once_with(self.config,self.manifest)
        self.assertEqual(before,self.manifest)

    def test_normal_import_still_requires_registered_reader(self):
        config=dict(self.config,role='import')
        with patch.object(service,'read_json',return_value=self.manifest):
            with self.assertRaises(ValueError):service.manifest_inputs(config)

    def test_rejoin_rejects_non_native_mode(self):
        with self.assertRaises(ValueError):service.validate_config(dict(self.config,mode='stored'))

    def test_ordinary_file_cannot_grant_rejoin_authority(self):
        with self.assertRaises(ValueError):rejoin.read_permit(dict(self.config,rejoinPermit='relative.json'))
        with self.assertRaises(ValueError):rejoin.read_permit(dict(self.config,rejoinPermit=str(Path(__file__).resolve())))

    def test_rejoin_release_cannot_substitute_for_registered_peer_release(self):
        receipt={'version':1,'ownerId':self.manifest['ownerId'],'readerId':'retained-b',
                 'manifestSha256':service.identity(self.manifest),'state':'released','scope':'readonly-rejoin-local-release'}
        with patch.object(service,'read_json',return_value=receipt):
            with self.assertRaises(ValueError):service.release_receipts({'operation':'retire','peerReceipts':['/receipt']},self.manifest)

    def test_control_loop_only_imports_and_retires_local_resources(self):
        # Exercise the existing service loop, overriding only the already
        # separately tested permit gate and the model's role configuration.
        original_serve=service.serve
        def serve_rejoin(config,selected,manifest):
            config=dict(config,role='rejoin',rejoinPermitSha256='sha256:'+'f'*64)
            with patch.object(service,'manifest_inputs',return_value=manifest):
                return original_serve(config,selected,manifest)
        with patch.object(service,'serve',side_effect=serve_rejoin):
            result=lifecycle.Lifecycle().exercise([lifecycle.Stream({'operation':'retire','peerReceipts':[]})])
        journal,receipts,cleanup,stopped,control,failure=result
        self.assertIsNone(failure)
        self.assertTrue(all(r.get('globalObjectDeletionAllowed') is False for r in journal))
        self.assertEqual(receipts[0]['scope'],'readonly-rejoin-local-release')
        self.assertEqual(cleanup,[{'readers_released':True}])
        self.assertEqual(journal[-1]['state'],'released')


if __name__=='__main__':unittest.main()
