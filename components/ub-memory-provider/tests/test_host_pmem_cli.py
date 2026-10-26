import contextlib
import io
from pathlib import Path
import types
import unittest
from unittest import mock

from aenv_ub_provider import host_pmem_cli as cli, raw


class PlanTests(unittest.TestCase):
    def config(self):
        source={'objectId':'image1','generation':'gen1','bytes':2**22,
                'sha256':'sha256:'+'a'*64,'socket':'/owned/data.sock'}
        base=Path(__file__).resolve().anchor
        return {'version':1,'workDir':str(Path(base)/'hp'/'run1'),
                'releaseReceipt':str(Path(base)/'hp'/'release.json'),'source':source,
                'ownerUid':1204,'ownerPid':50,'ownerStartTicks':'1234',
                'kernelRelease':'test-kernel','moduleSrcversion':'A'*24,
                'testFile':{'name':'payload.bin','bytes':4096,'sha256':'d'*64},
                'publication':{'version':1,'ownerId':'b'*32,'mode':'pmem','readers':['node-b'],
                               'replicas':[raw.shape(source,'aenv_'+'c'*32)]}}

    def test_plan_does_not_instantiate_session_or_allocate(self):
        with mock.patch.object(cli,'MountedSession',side_effect=AssertionError('mutation forbidden')):
            result=cli.plan(self.config())
        self.assertEqual(result['state'],'host_pmem_plan_no_action')
        self.assertFalse(result['SDKAllocationIncluded'])
        self.assertFalse(result['twoNodeAccepted'])

    def test_plan_digest_changes_with_owner_or_source_identity(self):
        config=self.config();before=cli.plan(config)['configSha256']
        config['ownerPid']+=1
        self.assertNotEqual(before,cli.plan(config)['configSha256'])

    def test_path_escape_and_invalid_identities_rejected(self):
        for key,value in (('ownerUid',0),('ownerPid',True),('moduleSrcversion','unknown')):
            config=self.config();config[key]=value
            with self.assertRaises(ValueError):cli.plan(config)
        config=self.config();config['testFile']['name']='../outside'
        with self.assertRaises(ValueError):cli.plan(config)

    def exercise_server(self, wrong_first=False, lost_reply=False, busy_first=False):
        config=self.config();pin=cli.plan(config)['configSha256']
        session=mock.Mock(work=Path(config['workDir']))
        first,second=mock.MagicMock(),mock.MagicMock()
        for stream in (first,second):stream.__enter__.return_value=stream
        listener=mock.Mock();listener.accept.side_effect=[(first,None),(second,None)]
        requests=[{'operation':'retire','configSha256':'wrong' if wrong_first else pin},
                  {'operation':'retire','configSha256':pin}]
        if busy_first:session.retire.side_effect=[RuntimeError('volume busy'),None]
        output=[]
        def send(stream,reply):
            output.append(reply)
            if lost_reply:raise BrokenPipeError('client gone')
        with contextlib.ExitStack() as stack:
            for target,name,value in (
                    (cli,'os',types.SimpleNamespace(getuid=lambda:0,geteuid=lambda:0,getpid=lambda:60,chmod=lambda *a:None)),
                    (cli.platform,'release',mock.Mock(return_value=config['kernelRelease'])),
                    (cli.Path,'stat',mock.Mock(return_value=types.SimpleNamespace(st_dev=1,st_ino=2))),
                    (cli.Path,'exists',mock.Mock(return_value=False)),
                    (cli,'MountedSession',mock.Mock(return_value=session)),
                    (cli,'socket',types.SimpleNamespace(AF_UNIX=1,SOCK_STREAM=1,socket=mock.Mock(return_value=listener))),
                    (cli,'root_peer',mock.Mock()),
                    (cli.host_pmem_lease,'process_ticks',mock.Mock(return_value='4567')),
                    (cli.contract,'receive_json',mock.Mock(side_effect=requests)),
                    (cli.contract,'send_json',mock.Mock(side_effect=send))):
                stack.enter_context(mock.patch.object(target,name,value))
            # Return the real source-specific sysfs values without any I/O.
            stack.enter_context(mock.patch.object(cli.Path,'read_text',autospec=True,
                side_effect=lambda path,*a,**k:'Y' if str(path).endswith('pmem_ro_enable') else config['moduleSrcversion']))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            cli.serve(config,pin)
        return session,listener,output

    def test_wrong_request_does_not_retire_but_next_explicit_request_can(self):
        session,listener,output=self.exercise_server(wrong_first=True)
        self.assertEqual(output[0]['state'],'retirement_refused_preserve_resources')
        session.retire.assert_called_once();session.export_release.assert_called_once()
        listener.close.assert_called_once()

    def test_busy_retirement_keeps_control_loop_and_never_exports_early_receipt(self):
        session,_,output=self.exercise_server(busy_first=True)
        self.assertEqual(output[0]['state'],'retirement_refused_preserve_resources')
        self.assertEqual(session.retire.call_count,2)
        session.export_release.assert_called_once()

    def test_lost_completion_reply_does_not_repeat_cleanup(self):
        session,listener,output=self.exercise_server(lost_reply=True)
        session.retire.assert_called_once();session.export_release.assert_called_once()
        self.assertEqual(listener.accept.call_count,1)
        self.assertEqual(output[0]['state'],'local_resources_released')


if __name__=='__main__':unittest.main()
