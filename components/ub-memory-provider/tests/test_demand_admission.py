"""Metadata-admission tests; root transport is a declared mock boundary."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest import mock

from aenv_ub_provider.demand_service import NodeAgent
from aenv_ub_provider.demand_wire import Layer
from aenv_ub_provider.host_dax_demand import Manifest,canonical,MIB


class AdmissionTests(unittest.TestCase):
    def agent(self):
        digest=hashlib.sha256(b'x'*4096).hexdigest()
        doc=dict(version=1,layerDigest='sha256:'+digest,fileBytes=4096,chunkBytes=4096,
                 chunks=[dict(index=0,offset=0,length=4096,sha256=digest)])
        manifest=Manifest(doc,hashlib.sha256(canonical(doc)).hexdigest())
        path='C:/d.sock' if os.name=='nt' else '/run/d.sock'
        layer=Layer(path,'aenv_'+'a'*32,'b'*32,'sha256:'+digest,4096,4*MIB,'sha256:'+manifest.sha256)
        registry=mock.Mock()
        registry.factory.supervisor.call.return_value={'body':{},'mac':'fixture'}
        agent=NodeAgent([layer],{manifest.sha256:manifest},registry,
                        Path(tempfile.gettempdir())/('absent-demand-index-'+uuid.uuid4().hex),1204)
        return agent,registry

    def test_no_broker_or_index_before_both_roots_ready(self):
        agent,registry=self.agent()
        registry.coordinator.call.side_effect=[{'state':'WAITING_FOR_PEER'},
            {'state':'SERVING','readyNodes':['a'],'requiredNodes':['a','b']}]
        with mock.patch('aenv_ub_provider.demand_service.time.monotonic',side_effect=[0,301]), \
             mock.patch('aenv_ub_provider.demand_service.atomic_json') as save, \
             mock.patch.object(agent.broker,'start') as start:
            with self.assertRaisesRegex(ValueError,'Peer root frontend'):agent.start()
            start.assert_not_called();save.assert_not_called()
        registry.read.assert_not_called()

    def test_both_ready_publishes_metadata_without_a_data_read(self):
        agent,registry=self.agent()
        registry.coordinator.call.side_effect=[{'state':'READY'},
            {'state':'SERVING','readyNodes':['a','b'],'requiredNodes':['a','b']}]
        with mock.patch('aenv_ub_provider.demand_service.atomic_json') as save, \
             mock.patch.object(agent.broker,'start') as start:
            result=agent.start()
            self.assertEqual(result['dataObjectsCreated'],0)
            self.assertEqual(save.call_args.args[1]['state'],'metadata_ready')
            start.assert_called_once()
        registry.read.assert_not_called()
        registry.factory.open.assert_not_called()


if __name__=='__main__':unittest.main()
