import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import sys
import types

P=Path(__file__).with_name('AB_reboot_readiness_v1.py')
s=importlib.util.spec_from_file_location('readiness',P)
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)


class Checks(unittest.TestCase):
    def test_changed_machine_rejected_before_observation(self):
        class API:
            @staticmethod
            def identity():
                return {'hostname':'server1','machineId':'different','gid':1205,
                        'uid':1204,'architecture':'aarch64','bootId':'new'}
        config={'node':'node-a','sessionId':m.SESSION,
                'identity':dict(API.identity(),machineId='old')}
        with patch.object(m,'unit',side_effect=AssertionError('must not inspect')):
            with self.assertRaisesRegex(RuntimeError,'Physical node'):
                m.inspect(API,config)

    def test_private_state_projection_excludes_keys(self):
        value={'phase':'sdk_start_intent','ownerId':'known', 'api_key':'secret',
               'peerToken':'secret', 'arbitrary':{'payload':'secret'}}
        with patch.object(m,'file_info',return_value={'sha256':None}), \
             patch.object(m,'read',return_value=json.dumps(value).encode()):
            r=m.json_projection('/unused')
        self.assertEqual(r['summary'],{'phase':'sdk_start_intent','ownerId':'known'})
        self.assertNotIn('secret',json.dumps(r))

    def test_only_service_metadata_command(self):
        class Result:
            returncode=0
            stdout='LoadState=loaded\nActiveState=inactive\n'
        with patch.object(m.subprocess,'run',return_value=Result()) as run:
            row=m.unit('ubse.service')
        self.assertEqual(run.call_args.args[0][:2],['/usr/bin/systemctl','show'])
        self.assertEqual(row['properties']['ActiveState'],'inactive')
        self.assertEqual(run.call_args.kwargs['stdin'],m.subprocess.DEVNULL)

    def test_large_container_not_attested(self):
        import tempfile
        with tempfile.TemporaryDirectory(dir=P.parent) as tmp:
            p=Path(tmp)/'container.ext4'
            p.write_bytes(b'abc')
            row=m.file_info(p,False,[0])
        self.assertIsNone(row['sha256'])
        self.assertEqual(row['hashStatus'],'metadata_only')

    def test_no_mutation_or_sdk_execution_in_observer(self):
        import ast
        tree=ast.parse(P.read_text(encoding='utf-8'))
        commands=[n for n in ast.walk(tree) if isinstance(n,ast.Call)
                  and isinstance(n.func,ast.Attribute) and n.func.attr=='run']
        self.assertEqual(len(commands),1)
        self.assertNotIn('ctypes',P.read_text())
        self.assertNotIn('os.chmod',P.read_text())
        self.assertNotIn('os.kill',P.read_text())


class FixedStartChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p=P.with_name('AB_upgrade_fixed_start_v1.py')
        s=importlib.util.spec_from_file_location('wrapper',p)
        cls.w=importlib.util.module_from_spec(s)
        with patch.dict(sys.modules,{'fcntl':types.SimpleNamespace()}):
            s.loader.exec_module(cls.w)
        cls.raw=p.read_bytes()

    def identities(self):
        old={'uid':1204,'gid':1205,'machineId':'same','hostname':'server1',
             'architecture':'aarch64','kernel':'old-kernel','bootId':'old'}
        config={'node':'node-a','sessionId':m.SESSION,'identity':old,
                'controlRepo':m.CONTROL[0],'controlRepoId':m.CONTROL[1],
                'resultRepo':m.RESULTS[0],'resultRepoId':m.RESULTS[1],
                'controlBranch':'main','resultBranch':'main'}
        return config,dict(old,bootId='new',kernel='new-kernel')

    def test_embedded_readiness_is_exact_published_source(self):
        self.assertEqual(self.w.payload().READINESS_SHA if hasattr(self.w.payload(),'READINESS_SHA') else
                         self.w.READINESS_SHA,__import__('hashlib').sha256(P.read_bytes()).hexdigest())

    def test_new_boot_only_permits_observation_not_new_machine(self):
        config,current=self.identities()
        self.w.validate_physical(config,current)
        with self.assertRaisesRegex(RuntimeError,'Physical node'):
            self.w.validate_physical(config,dict(current,machineId='other'))

    def api(self):
        import datetime
        import hashlib
        return types.SimpleNamespace(
            encoded=lambda v:(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n').encode(),
            digest=lambda b:hashlib.sha256(b).hexdigest(),
            timestamp=lambda t:datetime.datetime.fromisoformat(t).timestamp())

    def request_acceptance(self):
        config,current=self.identities();api=self.api()
        req={'node':'node-a','sessionId':m.SESSION,'identity':current,
             'previousIdentity':config['identity'],'receiptSha256':'a'*64,
             'wrapperSha256':'b'*64,'priorJobs':[{'state':'uploaded'}]}
        a={k:req[k] for k in ('node','sessionId','identity','previousIdentity',
                            'receiptSha256','wrapperSha256')}
        a.update(schema=1,priorJobsReviewed=True,requestSha256=api.digest(api.encoded(req)),
                 notBefore='2026-10-30T00:00:00+00:00',expiresAt='2026-10-31T00:00:00+00:00')
        return api,req,a

    def test_explicit_acceptance_binds_exact_receipt_and_boot(self):
        api,req,a=self.request_acceptance();now=api.timestamp('2026-10-30T12:00:00+00:00')
        self.w.validate_acceptance(api,a,req,now)
        with self.assertRaisesRegex(RuntimeError,'binding differs'):
            self.w.validate_acceptance(api,dict(a,identity={'bootId':'other'}),req,now)

    def test_expired_acceptance_does_not_launch(self):
        api,req,a=self.request_acceptance()
        with self.assertRaisesRegex(RuntimeError,'expired'):
            self.w.validate_acceptance(api,a,req,api.timestamp('2026-11-01T00:00:00+00:00'))

    def test_unknown_historical_job_never_cleared(self):
        api,req,a=self.request_acceptance();req['priorJobs']=[{'state':'running'}]
        a['requestSha256']=api.digest(api.encoded(req))
        with self.assertRaisesRegex(RuntimeError,'Old job outcome'):
            self.w.validate_acceptance(api,a,req,api.timestamp('2026-10-30T12:00:00+00:00'))

    def test_no_acceptance_uploads_only_and_never_fetches_job(self):
        config,current=self.identities();api=self.api();calls=[]
        report={'identity':current,'node':'node-a'}
        class Client:
            def private_repo(self,*args):pass
            def immutable_result(self,*args):calls.append(args[3])
            def contents(self,*args):
                selfpath=args[1]
                if selfpath.startswith('reboot-acceptances/'):return 404,None,None
                raise AssertionError('No profile, queue or task may be fetched before acceptance')
        api.GitHub=lambda token:Client()
        api.load=lambda p,private=False: {'controlToken':'hidden-control','resultToken':'hidden-result'} \
             if p.name=='credentials.json' else report
        r=types.SimpleNamespace(read=lambda p,limit:self.raw)
        def exists(p):return p.name!='stop.request'
        with patch.object(self.w.Path,'exists',exists), \
             patch.object(self.w,'history',return_value=[]):
            self.w.turn(api,r,config,current)
        self.assertEqual(len(calls),2)
        self.assertTrue(calls[0].startswith('reboot-readiness/'))
        self.assertTrue(calls[1].startswith('reboot-requests/'))

    def test_fixed_launcher_has_no_enroll_gate_or_token_prompt(self):
        text=self.w.launcher(self.w.BASE/'reboot-start-1234.py').decode()
        self.assertEqual(text.count('exec /usr/bin/python3'),1)
        self.assertNotIn(' enroll ',text)
        self.assertNotIn('token',text)


if __name__=='__main__':unittest.main()
