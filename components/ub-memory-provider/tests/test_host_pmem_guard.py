import copy
import unittest
from unittest import mock

from aenv_ub_provider import host_pmem_guard as g, raw


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.source={'objectId':'image1','generation':'gen1','sha256':'sha256:'+'a'*64,
                     'bytes':2**22,'socket':'/owned/data.sock'}
        self.manifest={'version':1,'ownerId':'b'*32,'mode':'pmem','readers':['node-b'],
                       'replicas':[raw.shape(self.source,'aenv_'+'c'*32)]}
        self.session={'phase':'local_resources_released','publication':g.publication_binding(self.manifest,self.source),
                      'source':self.source,'ownerUid':1204,'ownerPid':50,'ownerStartTicks':'1234','bootId':'boot1',
                      'volume':{'phase':'local_volume_absent','uuid':'8ea26803-3d68-4d17-8c13-e88c846e3802',
                                'status':{'id':7}},'mount':{'phase':'mount_absent'},
                      'sharedBackingReleaseAuthorized':False}

    def check(self,value):g.check_release(value,self.manifest,self.source,1204,50,'1234','boot1')

    def test_complete_local_release_matches_exact_provider_and_generation(self):
        value=g.release_record(self.session)
        self.check(value)
        self.assertFalse(value['sharedBackingReleaseAuthorized'])

    def test_mount_volume_or_session_not_retired_cannot_export_receipt(self):
        for key in ('volume','mount'):
            value=copy.deepcopy(self.session);value[key]['phase']='unknown'
            with self.assertRaises(ValueError):g.release_record(value)
        value=copy.deepcopy(self.session);value['phase']='retirement_stopped_preserve_resources'
        with self.assertRaises(ValueError):g.release_record(value)

    def test_wrong_owner_process_boot_or_false_release_rejected(self):
        for key,replacement in (('ownerUid',0),('ownerPid',51),('ownerStartTicks','1235'),('bootId','boot2'),
                                ('state','serving'),('mountAbsent',False),('localVolumeAbsent',False),
                                ('sharedBackingReleaseAuthorized',True),('volumeId',True)):
            value=g.release_record(self.session);value[key]=replacement
            with self.assertRaises(ValueError,msg=key):self.check(value)

    def test_same_contents_in_different_publication_are_not_same_release(self):
        value=g.release_record(self.session)
        self.manifest['ownerId']='d'*32
        with self.assertRaises(ValueError):self.check(value)

    def test_recreated_sdk_object_not_accepted_even_with_same_sha(self):
        value=g.release_record(self.session)
        self.manifest['replicas'][0]['objectName']='aenv_'+'e'*32
        with self.assertRaises(ValueError):self.check(value)

    def test_other_socket_or_unknown_image_not_accepted(self):
        value=g.release_record(self.session)
        value['source']={**self.source,'socket':'/different/data.sock'}
        with self.assertRaises(ValueError):self.check(value)
        source={**self.source,'generation':'other'}
        with self.assertRaises(ValueError):g.publication_binding(self.manifest,source)

    def test_failure_before_create_can_release_without_fabricating_volume_id(self):
        self.session['volume']={'phase':'not_attempted'}
        self.session['mount']={'phase':'not_attempted'}
        value=g.release_record(self.session)
        self.assertFalse(value['volumeCreated']);self.assertIsNone(value['volumeUuid'])
        self.check(value)
        value['volumeId']=0
        with self.assertRaises(ValueError):self.check(value)

    def test_unknown_creation_cannot_be_relabelled_never_created(self):
        self.session['volume']={'phase':'create_intent'}
        self.session['mount']={'phase':'not_attempted'}
        with self.assertRaises(ValueError):g.release_record(self.session)

    def test_queried_absence_preserves_unknown_creation_instead_of_faking_never_created(self):
        self.session['volume']={'phase':'local_volume_absent','absenceQueried':True,
                                'uuid':'8ea26803-3d68-4d17-8c13-e88c846e3802'}
        self.session['mount']={'phase':'not_attempted'}
        value=g.release_record(self.session)
        self.assertIsNone(value['volumeCreated'])
        self.assertEqual(value['creationOutcome'],'creation_unconfirmed_now_absent')
        self.check(value)

    def test_terminal_cancellation_binds_exact_maintenance_epoch(self):
        from aenv_ub_provider.service import identity
        receipt={'version':1,'scope':'host-pmem-reader-cancel','state':'not_imported',
                 'ownerId':self.manifest['ownerId'],'manifestSha256':identity(self.manifest),
                 'readerId':'node-b','epoch':'e'*32,'sdkImportAttempted':False,'terminal':True}
        epochs={'node-b':'e'*32}
        self.assertEqual(g.check_cancelled_reader(receipt,self.manifest,epochs),'node-b')
        for key,value in (('epoch','f'*32),('sdkImportAttempted',True),('terminal',False),
                          ('manifestSha256','wrong'),('state','released')):
            changed={**receipt,key:value}
            with self.assertRaises(ValueError):g.check_cancelled_reader(changed,self.manifest,epochs)

    def test_cancellation_requires_opt_in_and_root_receipt_check(self):
        from aenv_ub_provider import service
        request={'operation':'retire','peerReceipts':['cancel.json']}
        receipt={'scope':'host-pmem-reader-cancel'}
        with mock.patch.object(service,'read_json',return_value=receipt):
            with self.assertRaises(ValueError):service.release_receipts(request,self.manifest)
            with mock.patch.object(g,'require_cancelled_reader',side_effect=ValueError('not root-owned')) as guard:
                with self.assertRaises(ValueError):service.release_receipts(request,self.manifest,{'node-b':'e'*32})
                guard.assert_called_once()


if __name__=='__main__':unittest.main()
