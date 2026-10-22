import copy
import importlib.util
import io
import stat
from pathlib import Path
import types
import unittest
from unittest import mock

spec=importlib.util.spec_from_file_location('stop',Path(__file__).with_name('lazy_four_stop_v2.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def states():
    return {node:{'guestsReleased':True,'runtime':{'MainPID':'10'},'providerUnit':{'MainPID':'20'},
        'provider':{'state':'serving','cacheId':'same','pool':{'objectName':'owned','mappingBytes':256},
                    'finalizeAcknowledged':False,'deleteAcknowledged':False},
        'rootTicks':'old-'+node,'metadataSocketPresent':node=='node-b'} for node in ('node-a','node-b')}


class StopTests(unittest.TestCase):
    def test_new_root_reply_contract_is_scoped_to_stop_and_finish(self):
        reply={'status':'ROOT_OPERATION_COMPLETED','nonce':'known','sequence':633,'operation':'runtime-stop',
               'result':{'state':'own-runtime-and-proxy-stopped'}}
        m.validate_a_ack(reply,'known',633,'runtime-stop')
        for change in ({'nonce':'other'},{'sequence':634},{'operation':'runtime-lazy'},
                       {'status':'ROOT_OPERATION_STOPPED_PRESERVE_STATE'}):
            with self.assertRaises(RuntimeError):m.validate_a_ack(dict(reply,**change),'known',633,'runtime-stop')
        with self.assertRaises(RuntimeError):m.validate_a_ack(reply,'known',633,'observe')

    def test_user_owned_new_reply_still_refused(self):
        path=mock.MagicMock();path.is_relative_to.return_value=True;path.resolve.return_value=path
        class Stream(io.BytesIO):
            def fileno(self):return 7
        meta=types.SimpleNamespace(st_mode=stat.S_IFREG|0o644,st_uid=1204,st_size=2,st_ino=1,st_mtime_ns=1)
        with (mock.patch.object(m.os,'open',return_value=7),mock.patch.object(m.os,'fdopen',return_value=Stream(b'{}')),
              mock.patch.object(m.os,'fstat',return_value=meta),mock.patch.object(m.os,'O_NOFOLLOW',0,create=True),
              mock.patch.object(m.os,'O_NONBLOCK',0,create=True)):
            with self.assertRaisesRegex(RuntimeError,'Unexpected cleanup input'):m.read(path,owner=0)

    def test_recovered_channel_never_reads_ready_or_changes_ownership(self):
        import inspect
        source=inspect.getsource(m.recovered_a_request)
        self.assertNotIn("read(mailbox/'ready.json'",source)
        self.assertIn('A_SCOPE_SHA',source)
        self.assertIn('read(response,owner=0',source)
        self.assertNotIn('chown(',source)
        self.assertNotIn('chmod(',source)
        self.assertIn("operation in ('runtime-stop','finish')",source)

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
        self.assertEqual(events,[('node-a','runtime-stop'),('node-b','runtime-stop'),('node-b','retire'),('node-a','retire'),
                                 ('node-b','finish'),('node-a','finish'),('node-a','stop-metadata')])
        self.assertEqual(saved[-1]['status'],'OWN_LAZY_EXPERIMENT_STOPPED_AND_UB_RELEASED')
        self.assertTrue(saved[-1]['reportsAndSnapshotsPreserved'])


if __name__=='__main__':unittest.main()
