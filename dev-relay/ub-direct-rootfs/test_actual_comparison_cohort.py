"""Synthetic API contracts only; no target or Guest actions."""
import copy,types,unittest
from pathlib import Path
import actual_comparison_cohort as cohort
ENGINE=types.ModuleType('pinned_cohort')
path=Path(__file__).resolve().parent.parent/'lazy-four-20261022/delivery/cohort_engine.py'
exec(compile(path.read_bytes(),str(path),'exec'),ENGINE.__dict__)

class API:
    def __init__(self,fail_second=False):self.rows={};self.posts=[];self.fail_second=fail_second
    def call(self,method,path,body=None,**kw):
        if method=='GET' and path=='/v2/sandboxes?limit=1':return 200,list(self.rows.values())
        if method=='GET':return (200,self.rows[path.rsplit('/',1)[-1]]) if path.rsplit('/',1)[-1] in self.rows else (404,None)
        if method=='POST':
            self.posts.append(copy.deepcopy(body))
            if self.fail_second and len(self.posts)==2:return 500,{'error':'fixture'}
            sid='guest-'+str(len(self.posts));row={'sandboxID':sid,'metadata':body['metadata']};self.rows[sid]=row
            return 201,row
        raise AssertionError('Unexpected request')

class NativeCohortContracts(unittest.TestCase):
    def make(self,api):
        template={'templateIndex':0,'templateId':'template','resources':{'cpu_count':2,'memory_mib':4096},
                  'catalogSha256':'a'*64,'replaySha256':'b'*64,'rootfsLayers':[{'digest':'sha256:'+'c'*64,'size':1234}]}
        saved=[]
        instance=cohort.ActualComparisonCohort(api,ENGINE,None,None,None,Path('/home/jwk/agent/fixture'),
            'original',[template],{},lambda index,value:saved.append((index,copy.deepcopy(value))),lambda *a:None)
        instance.guard=lambda:None
        return instance,saved

    def test_exact_two_owned_restores_and_no_cold_capture(self):
        api=API();instance,saved=self.make(api);jobs=instance.restore('a'*32)
        self.assertEqual(len(jobs),2);self.assertEqual([r['slot'] for r in jobs],[0,1])
        self.assertEqual({r['templateID'] for r in api.posts},{'template'})
        self.assertTrue(all(r['timeout']==7200 and r['autoPause'] is False for r in api.posts))
        self.assertEqual(instance.owned(jobs[0]['sandboxId'])['sandboxID'],jobs[0]['sandboxId'])
        self.assertTrue(any(state['openRequests'] for _,state in saved))
        self.assertEqual(instance.cases[0].state['openRequests'],[])

    def test_unknown_create_is_retained_and_never_retried(self):
        api=API(True);instance,saved=self.make(api)
        with self.assertRaises(RuntimeError):instance.restore('a'*32)
        state=instance.cases[0].state
        self.assertEqual(state['sandboxIds'],['guest-1']);self.assertEqual(len(state['openRequests']),1)
        self.assertTrue(state['outcomeUncertain']);self.assertEqual(len(api.posts),2)
        with self.assertRaises(RuntimeError):instance.restore('a'*32)
        self.assertEqual(len(api.posts),2)

    def test_full_binding_never_accepts_fallback_or_old_generation(self):
        expected=[{'digest':'sha256:'+'a'*64,'size':1234}]
        ref={'layerDigest':expected[0]['digest'],'fileBytes':1234,'generation':'b'*32,'allowRepositoryFallback':False}
        index={'version':1,'state':'ready','replicas':[ref]}
        config={'lowers':[{**expected[0],'ub':copy.deepcopy(ref)}]}
        cohort.check_binding(config,expected,'full',index)
        config['lowers'][0]['ub']['generation']='c'*32
        with self.assertRaises(RuntimeError):cohort.check_binding(config,expected,'full',index)
        config['lowers'][0]['ub']=copy.deepcopy(ref);index['replicas'][0]['allowRepositoryFallback']=True
        with self.assertRaises(RuntimeError):cohort.check_binding(config,expected,'full',index)

    def test_original_cannot_have_ub_reference(self):
        expected=[{'digest':'sha256:'+'a'*64,'size':1234}]
        config={'lowers':[{**expected[0]}]};cohort.check_binding(config,expected,'original',None)
        config['lowers'][0]['ub']={}
        with self.assertRaises(RuntimeError):cohort.check_binding(config,expected,'original',None)

    def test_failed_replay_cannot_trigger_automatic_cleanup(self):
        api=API();instance,_=self.make(api)
        with self.assertRaises(RuntimeError):instance.release_after_completed_replay({'status':'FAILED','pendingCommands':1})
        self.assertEqual(api.posts,[])

    def test_missing_file_measurement_scope_fails_before_observation(self):
        instance,_=self.make(API())
        instance.observe=lambda:(_ for _ in ()).throw(AssertionError('Should not observe yet'))
        with self.assertRaises(RuntimeError):instance.sampling_scope('a',[],{}, {})

if __name__=='__main__':unittest.main()
