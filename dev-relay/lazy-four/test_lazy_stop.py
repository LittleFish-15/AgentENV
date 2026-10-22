import copy
import importlib.util
import io
from pathlib import Path
import types
import unittest
from unittest import mock

spec=importlib.util.spec_from_file_location('stop',Path(__file__).with_name('lazy_four_stop.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def states():
    return {node:{'guestsReleased':True,'runtime':{'MainPID':'10'},'providerUnit':{'MainPID':'20'},
        'provider':{'state':'serving','cacheId':'same','pool':{'objectName':'owned','mappingBytes':256},
                    'finalizeAcknowledged':False,'deleteAcknowledged':False},
        'rootTicks':'old-'+node,'metadataSocketPresent':node=='node-b'} for node in ('node-a','node-b')}


class StopTests(unittest.TestCase):
    def test_mismatched_or_already_changed_generation_refused(self):
        value=states();m.validate_pair(value['node-a'],value['node-b'])
        value['node-b']['provider']['cacheId']='other'
        with self.assertRaises(RuntimeError):m.validate_pair(value['node-a'],value['node-b'])
        value=states();value['node-a']['provider']['state']='released'
        with self.assertRaises(RuntimeError):m.validate_pair(value['node-a'],value['node-b'])

    def test_owner_requires_delete_and_finalize_ack(self):
        value=states()['node-a'];value['provider'].update(state='released',finalizeAcknowledged=True)
        self.assertTrue(m.released(value,'node-b'))
        self.assertFalse(m.released(value,'node-a'))
        value['provider']['deleteAcknowledged']=True
        self.assertTrue(m.released(value,'node-a'))

    def test_cleanup_order_and_no_new_test_actions(self):
        value=states();events=[];saved=[]
        def command(node,operation):
            events.append((node,operation))
            if operation=='runtime-stop':value[node]['runtime']['MainPID']='0'
            elif operation=='finish':value[node]['rootTicks']=None
            else:self.fail('Unexpected root mutation')
            return {'acknowledged':True}
        def run(argv,**kwargs):
            node='node-b' if argv[0]=='remote-retire-b' else 'node-a'
            events.append((node,'retire'))
            value[node]['provider'].update(state='released',finalizeAcknowledged=True,deleteAcknowledged=node=='node-a')
            value[node]['providerUnit']['MainPID']='0'
            return types.SimpleNamespace(returncode=0)
        def metadata(scope):
            events.append(('node-a','stop-metadata'));value['node-b']['metadataSocketPresent']=False
            return {'ownedLeaderExited':True}
        scope={'save':lambda p,r:saved.append(copy.deepcopy(r)),'root_command':command,
               'remote_command':lambda args:['remote-retire-b']}
        with (mock.patch.multiple(m,coordinator=lambda:scope,inspect_node=lambda node:copy.deepcopy(value[node]),
                remote_inspect=lambda scope:copy.deepcopy(value['node-b']),stop_metadata=metadata),
              mock.patch.object(m.os,'getuid',return_value=1204,create=True),mock.patch.object(m.os,'geteuid',return_value=1204,create=True),
              mock.patch.object(m.os,'umask'),mock.patch.object(m.socket,'gethostname',return_value='server1'),
              mock.patch.object(m.subprocess,'run',side_effect=run),mock.patch.object(Path,'exists',return_value=False),
              mock.patch.object(Path,'is_symlink',return_value=False),mock.patch.object(Path,'open',side_effect=lambda *a,**k:io.BytesIO()),
              mock.patch('sys.argv',['lazy_four_stop.py','--run']),mock.patch('builtins.print')):
            m.main()
        self.assertEqual(events,[('node-b','runtime-stop'),('node-a','runtime-stop'),('node-b','retire'),('node-a','retire'),
                                 ('node-b','finish'),('node-a','finish'),('node-a','stop-metadata')])
        self.assertEqual(saved[-1]['status'],'OWN_LAZY_EXPERIMENT_STOPPED_AND_UB_RELEASED')
        self.assertTrue(saved[-1]['reportsAndSnapshotsPreserved'])


if __name__=='__main__':unittest.main()
