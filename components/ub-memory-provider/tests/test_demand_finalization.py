"""Finalization and signed root-control release gates, mocked OS boundaries."""
from pathlib import Path
import threading
import unittest
from unittest import mock

from aenv_ub_provider.demand_control import Coordinator,proof_mac
from aenv_ub_provider.demand_views import RootSupervisor


class Publisher:
    def __init__(self):self.finalized=False
    def finalize(self):self.finalized=True


class FinalizationTests(unittest.TestCase):
    def test_owner_waits_for_node_finalize_ack_then_signs_root_release(self):
        publisher=Publisher()
        with mock.patch.object(Path,'mkdir'),mock.patch('aenv_ub_provider.demand_control.atomic_json'):
            owner=Coordinator('a'*32,{},publisher,'unused',['a','b'],{'a':b'k'*32,'b':b'k'*32},
                              image_key=b'i'*32,owner_node='a')
            def call(node,method,params=None):
                return owner.dispatch(node,{'run':'a'*32,'method':method,'operation':'b'*32,'params':params or {}})
            for node in ('a','b'):
                body=dict(version=1,kind='demand-root-ready',run='a'*32,node=node,rootControlPinned=True,
                          bootId='fixture',kernelRelease='fixture',moduleSrcversion='fixture')
                call(node,'ready',{'root':{'body':body,'mac':proof_mac(b'k'*32,body)}})
            call('a','close-admission')
            call('a','node-drained',{'source':{'disposition':'owner_anchor_retained'}})
            with self.assertRaisesRegex(ValueError,'finalization'):
                call('a','finish')
            self.assertFalse(publisher.finalized)
            with self.assertRaisesRegex(ValueError,'finalization'):
                call('b','node-drained',{'source':{'disposition':'importer_finalized','finalizeAcknowledged':False}})
            call('b','node-drained',{'source':{'disposition':'importer_finalized','finalizeAcknowledged':True}})
            result=call('a','finish')
            self.assertTrue(publisher.finalized)
            proof=result['rootReleaseReceipt']
            self.assertEqual(proof['mac'],proof_mac(b'i'*32,proof['body']))
            self.assertEqual(call('a','finish')['rootReleaseReceipt'],proof)

    def test_root_control_requires_global_ack_and_no_live_local_views(self):
        root=RootSupervisor.__new__(RootSupervisor)
        root.config={'run':'a'*32,'node':'b','ownerNode':'a'}
        root.image_key=b'i'*32;root.lock=threading.RLock();root.control=123;root._save=mock.Mock()
        body=dict(version=1,kind='demand-global-released',run='a'*32,ownerNode='a',
                  globalObjectsReleased=True,ownerFinalizationAcknowledged=True)
        proof={'body':body,'mac':proof_mac(root.image_key,body)}
        with mock.patch('aenv_ub_provider.demand_views.os.close') as close:
            root.records={'g':{'phase':'READY'}}
            with self.assertRaisesRegex(ValueError,'Local root views'):root.release_control(proof)
            close.assert_not_called()
            root.records['g']['phase']='RELEASED'
            with self.assertRaisesRegex(ValueError,'receipt'):root.release_control(dict(proof,mac='0'*64))
            close.assert_not_called()
            self.assertEqual(root.release_control(proof)['state'],'ROOT_CONTROL_RELEASED')
            root.release_control(proof)
            close.assert_called_once_with(123)


if __name__=='__main__':unittest.main()
