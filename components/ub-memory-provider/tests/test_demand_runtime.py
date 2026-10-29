"""Role assembly/config tests only; native boundaries are explicitly mocked."""
import hashlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aenv_ub_provider import demand_runtime as runtime
from aenv_ub_provider.host_dax_demand import canonical


def config():
    data = b'x'*4096
    digest = hashlib.sha256(data).hexdigest()
    document = {'version':1, 'layerDigest':'sha256:'+digest, 'fileBytes':len(data),
                'chunkBytes':4096, 'chunks':[{'index':0,'offset':0,'length':len(data),'sha256':digest}]}
    pin = hashlib.sha256(canonical(document)).hexdigest()
    return {'version':1,'role':'owner','run':'a'*32,'node':'a','nodes':['a','b'],'ownerNode':'a',
            'budgetBytes':128*1024**2,'stateRoot':str(Path(tempfile.gettempdir()).resolve()/'demand-test-state'),
            'manifests':[{'sha256':pin,'document':document,'sourcePath':str(Path(tempfile.gettempdir()).resolve()/'source')}],
            'adapter':'unused','adapterSha256':'b'*64,'region':'unused','mke2fs':'unused',
            'receiptKeys':{'a':'unused','b':'unused'},'imageKey':'unused',
            'tls':{'ca':'unused','certificate':'unused','key':'unused'},'listenHost':'127.0.0.1',
            'listenPort':19001,'nodeFingerprints':{'c'*64:'a','d'*64:'b'}}


class RuntimeTests(unittest.TestCase):
    def test_read_trace_is_bounded_and_reports_drops(self):
        stream=io.BytesIO()
        with mock.patch.object(Path,'open',return_value=stream):
            journal=runtime.ReadJournal('unused',limit=1)
        journal({'kind':'demand_read','requestedBytes':4096,'completedBytes':4096})
        self.assertEqual(stream.getvalue(),b'')
        self.assertEqual(journal.status()['dropped'],1)
        self.assertFalse(journal.status()['traceComplete'])

    def test_manifest_validation_does_not_open_payload_or_sdk(self):
        value = config()
        with mock.patch('aenv_ub_provider.demand_source.DirectSource', side_effect=AssertionError('source opened')):
            self.assertEqual(len(runtime.validate(value)), 1)

    def test_owner_requires_both_node_trust_and_bound_budget(self):
        for key, bad in [('budgetBytes',0),('node','b'),('receiptKeys',{'a':'unused'})]:
            value=config();value[key]=bad
            with self.assertRaises(ValueError):runtime.validate(value)

    def test_untrusted_manifest_is_rejected(self):
        value=config();value['manifests'][0]['document']['fileBytes']+=1
        with self.assertRaises(ValueError):runtime.validate(value)

    def test_missing_role_configuration_fails_before_assembly(self):
        value=config();del value['adapter']
        with self.assertRaises(ValueError):runtime.validate(value)

    def test_duplicate_manifest_is_rejected(self):
        value=config();value['manifests']*=2
        with self.assertRaises(ValueError):runtime.validate(value)

    def test_owner_assembly_does_not_initialize_sdk_or_read_source(self):
        value=config()
        with tempfile.TemporaryDirectory() as directory:
            value['stateRoot']=str(Path(directory).resolve()/'fresh')
            manifests=runtime.validate(value)
            with mock.patch.object(runtime,'key_file',return_value=b'x'*32), \
                 mock.patch('aenv_ub_provider.demand_control.server',return_value='http-server') as server, \
                 mock.patch('aenv_ub_provider.demand_source.DirectSource', side_effect=AssertionError('startup read')), \
                 mock.patch('aenv_ub_provider.demand_native.NativeChunkPublisher._initialize', side_effect=AssertionError('startup SDK')):
                self.assertEqual(runtime.assemble_owner(value,manifests),'http-server')
                coordinator=server.call_args.args[1]
                self.assertEqual(coordinator.cache.snapshot()['entries'],[])
                with self.assertRaises(FileExistsError):runtime.assemble_owner(value,manifests)


if __name__=='__main__':unittest.main()
