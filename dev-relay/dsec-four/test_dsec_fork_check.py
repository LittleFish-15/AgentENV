import copy, importlib.util, unittest, uuid
from pathlib import Path

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('fork_packet',HERE/'A_dsec_four_v3.py')
packet=importlib.util.module_from_spec(spec);spec.loader.exec_module(packet)
fork=packet.module('dsec_fork_check')
engine=fork.extend_engine(packet.module('cohort_engine'))


class Api:
    def __init__(self,mode='normal'):
        self.guests={};self.contents={};self.posts=[];self.maximum=0;self.mode=mode;self.deletes=[]
    def call(self,method,path,body=None,timeout=30):
        if method=='GET' and path=='/v2/sandboxes?limit=1':return 200,list(self.guests.values())
        if method=='POST':
            self.posts.append((path,copy.deepcopy(body)))
            if path.endswith('/fork'):
                source=path.split('/')[-2];rows=[]
                for i in range(2):
                    if self.mode=='partial' and i==1:
                        rows.append({'error':'fixture startup failure'});continue
                    sid=str(uuid.uuid4());self.guests[sid]={'sandboxID':sid,'metadata':copy.deepcopy(self.guests[source]['metadata'])}
                    self.contents[sid]=copy.deepcopy(self.contents[source]);rows.append({'sandbox':self.guests[sid]})
                self.maximum=max(self.maximum,len(self.guests))
                if self.mode=='lost':raise TimeoutError('Lost Fork reply')
                return 201,rows
            sid=str(uuid.uuid4());self.guests[sid]={'sandboxID':sid,'metadata':body['metadata']}
            self.contents[sid]={'marker':None,'base':'original'};self.maximum=max(self.maximum,len(self.guests))
            return 201,{'sandboxID':sid}
        sid=path.rsplit('/',1)[1]
        if method=='GET':return (200,self.guests[sid]) if sid in self.guests else (404,None)
        if method=='DELETE':self.guests.pop(sid,None);self.contents.pop(sid,None);self.deletes.append(sid);return 204,None
        raise AssertionError((method,path))


def case(api,persist=None):
    saved=[]
    def write(state):
        saved.append(copy.deepcopy(state))
        if persist:persist(state)
    value=engine.Cohort(api,{'version':1,'phase':'prepared','openRequests':[],'sandboxIds':[],
        'outcomeUncertain':False,'runtimeContext':{}},write,None,None,lambda _:None,lambda sid:None,
        run_id='a'*32)
    return value,saved


def execute(api,commands):
    def command(sid,label,mode):
        commands.append((sid,label,mode));data=api.contents[sid]
        if mode=='parent':data['marker']='parent'
        elif mode=='write':data.update(marker='child',base='private')
        elif mode=='private':assert data=={'marker':'child','base':'private'}
        elif mode=='check':assert data=={'marker':'parent','base':'original'}
        else:raise AssertionError(mode)
    return command


class Fork(unittest.TestCase):
    def test_one_two_child_request_and_survival_after_source_sibling_exit(self):
        api=Api();value,saved=case(api);commands=[]
        result=fork.exercise(value,{'nativeTemplateId':'clean'},execute(api,commands))
        self.assertEqual(api.maximum,3)
        self.assertEqual(api.posts[1][1]['count'],2);self.assertEqual(len(api.posts),2)
        self.assertTrue(result['childrenReadableAfterSourceExit']);self.assertTrue(result['survivorReadableAfterSiblingExit'])
        self.assertEqual(len(api.guests),1);self.assertEqual(len(api.deletes),2)
        value.recover_owned();self.assertFalse(api.guests);self.assertTrue(engine.quiescent(value.state))
        self.assertEqual(len(value.state['snapshots']),0)
        self.assertTrue(any(r.get('forkPairCompleteResponse') for s in saved for r in s['openRequests']))

    def test_lost_response_never_retries_or_invents_released_children(self):
        api=Api('lost');value,_=case(api)
        with self.assertRaises(TimeoutError):fork.exercise(value,{'nativeTemplateId':'clean'},execute(api,[]))
        value.recover_owned()
        self.assertEqual(len(api.posts),2);self.assertEqual(len(api.guests),2)
        self.assertTrue(value.state['outcomeUncertain']);self.assertFalse(engine.quiescent(value.state))

    def test_partial_response_cleans_known_source_and_child_keeps_uncertainty(self):
        api=Api('partial');value,_=case(api)
        with self.assertRaisesRegex(RuntimeError,'incomplete'):
            fork.exercise(value,{'nativeTemplateId':'clean'},execute(api,[]))
        value.recover_owned();self.assertFalse(api.guests)
        self.assertTrue(value.state['outcomeUncertain']);self.assertEqual(len(value.state['openRequests']),1)
        self.assertFalse(engine.quiescent(value.state))

    def test_durable_complete_response_recovers_after_client_interrupt(self):
        api=Api();fired=False
        def interrupt(state):
            nonlocal fired
            if not fired and any(r.get('forkPairCompleteResponse') for r in state['openRequests']):
                fired=True;raise RuntimeError('Client stopped after durable response')
        value,saved=case(api,interrupt)
        with self.assertRaisesRegex(RuntimeError,'Client stopped'):
            fork.exercise(value,{'nativeTemplateId':'clean'},execute(api,[]))
        recovered=engine.Cohort.recovery(api,saved[-1],lambda s:None)
        recovered.recover_owned();self.assertFalse(api.guests)
        self.assertTrue(engine.quiescent(recovered.state));self.assertEqual(len(api.posts),2)

    def test_guest_check_failure_still_cleans_all_known_guests(self):
        api=Api();value,_=case(api)
        command=execute(api,[])
        def failed(sid,label,mode):
            if label=='after-source-exit-0':raise RuntimeError('Guest check failed')
            command(sid,label,mode)
        with self.assertRaisesRegex(RuntimeError,'Guest check'):
            fork.exercise(value,{'nativeTemplateId':'clean'},failed)
        value.recover_owned();self.assertFalse(api.guests);self.assertTrue(engine.quiescent(value.state))

    def test_wrong_batch_acknowledgment_never_deletes_foreign_guest(self):
        api=Api();value,_=case(api)
        source=value.create('/v2/sandboxes',{'metadata':{'cow_batch':value.run_id}})
        foreign=str(uuid.uuid4());api.guests[foreign]={'sandboxID':foreign,'metadata':{'cow_batch':'foreign'}}
        request={'id':'b'*32,'kind':'fork_pair','sourceId':source,'route':'/sandboxes/'+source+'/fork',
                 'expectedCount':2,'forkPairAckIds':[foreign],'responseHttpStatus':201,'forkPairCompleteResponse':False}
        value.state['openRequests'].append(request);value.save();value.recover_owned()
        self.assertIn(foreign,api.guests);self.assertNotIn(foreign,api.deletes)
        self.assertTrue(value.state['outcomeUncertain'])

    def test_duplicate_response_and_source_alias_are_rejected(self):
        ids,complete=fork.response_ids(201,[{'sandbox':{'sandboxID':'a'}},{'sandbox':{'sandboxID':'a'}}])
        self.assertEqual(ids,['a']);self.assertFalse(complete)
        api=Api();value,_=case(api);source=value.create('/v2/sandboxes',{'metadata':{'cow_batch':value.run_id}})
        with self.assertRaisesRegex(RuntimeError,'aliases source'):
            fork.register_acknowledged(value,{'sourceId':source,'forkPairAckIds':[source]})

    def test_pending_request_blocks_new_fork(self):
        api=Api();value,_=case(api);source=value.create('/v2/sandboxes',{'metadata':{'cow_batch':value.run_id}})
        value.state['openRequests'].append({'kind':'create'})
        with self.assertRaisesRegex(RuntimeError,'uncertain'):fork.fork_pair(value,source)
        self.assertEqual(len(api.posts),1)


if __name__=='__main__':unittest.main()
