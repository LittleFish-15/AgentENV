import contextlib,copy,importlib.util,types,unittest,json,stat
from pathlib import Path
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('cow55_build_test',Path(__file__).with_name('cow55_build.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
ID='11111111-1111-1111-1111-111111111111'

class FakeApi:
    key='not-a-real-key'
    def __init__(self,responses):self.responses=list(responses);self.calls=[]
    def call(self,method,path,body=None):
        self.calls.append((method,path,body))
        value=self.responses.pop(0)
        if isinstance(value,Exception):raise value
        return value

class BuildTests(unittest.TestCase):
    def fixture(self,state='IMAGE_VERIFIED'):
        case={'state':state,'instance_id':'example','template_name':'swb-example-1','local_oci_directory':'/owned/image',
              'manifest_digest':'sha256:'+'1'*64,'template_id':ID,'build_id':ID}
        holder={'cases':[case]};writes=[]
        stack=contextlib.ExitStack();self.addCleanup(stack.close)
        for name,value in [('capacity',lambda:None),('empty',lambda api:None),('verify_layout',lambda *a:{}),('verify_ready',lambda case:case.update(verified=True)),
                           ('save',lambda value:writes.append(copy.deepcopy(value))),('H',types.SimpleNamespace(safe=lambda p:p,error_summary=lambda b,k:b))]:
            stack.enter_context(patch.object(m,name,value))
        return case,holder,writes
    def test_create_intent_written_before_API(self):
        case,holder,writes=self.fixture();api=FakeApi([TimeoutError('lost reply')])
        with self.assertRaises(TimeoutError):m.build_case(case,holder,api,Path('/owned'),{})
        self.assertEqual(writes[-1]['cases'][0]['state'],'CREATE_INTENT')
        self.assertEqual(len(api.calls),1)
        with self.assertRaisesRegex(RuntimeError,'Unresolved'):m.build_case(case,holder,api,Path('/owned'),{})
        self.assertEqual(len(api.calls),1)
    def test_original_API_recipe_and_resources(self):
        case,holder,writes=self.fixture();api=FakeApi([(202,{'templateID':ID,'buildID':ID}),(202,None),(200,{'status':'ready'})])
        m.build_case(case,holder,api,Path('/owned'),{})
        self.assertEqual(api.calls[0],('POST','/v3/templates',{'name':'swb-example-1','memoryMB':4096,'tags':[]}))
        self.assertNotIn('cpuCount',api.calls[0][2]);self.assertEqual(api.calls[1][2]['steps'],[])
        self.assertTrue(api.calls[1][2]['fromImage'].startswith('ocidir://'))
        self.assertEqual(case['state'],'READY');self.assertTrue(case['verified'])
    def test_uncertain_build_is_polled_never_reposted(self):
        case,holder,writes=self.fixture('BUILD_INTENT');api=FakeApi([(200,{'status':'ready'})])
        m.build_case(case,holder,api,Path('/owned'),{})
        self.assertEqual([v[0] for v in api.calls],['GET'])
    def test_timeout_retains_known_build(self):
        case,holder,writes=self.fixture('BUILDING');api=FakeApi([(200,{'status':'building'})])
        with self.assertRaisesRegex(RuntimeError,'pending'):m.build_case(case,holder,api,Path('/owned'),{},wait_seconds=0)
        self.assertEqual(case['state'],'WAITING_ASYNC');self.assertEqual(case['build_id'],ID)
    def test_build_error_prevents_repeat(self):
        case,holder,writes=self.fixture('BUILDING');api=FakeApi([(200,{'status':'error','reason':{'message':'failure'}})])
        with self.assertRaisesRegex(RuntimeError,'failed'):m.build_case(case,holder,api,Path('/owned'),{})
        self.assertEqual(case['state'],'BUILD_ERROR')
        with self.assertRaisesRegex(RuntimeError,'Unresolved'):m.build_case(case,holder,api,Path('/owned'),{})
        self.assertEqual(len(api.calls),1)
    def test_completed_case_only_verified(self):
        case,holder,writes=self.fixture('READY');api=FakeApi([]);m.build_case(case,holder,api,Path('/owned'),{})
        self.assertEqual(api.calls,[]);self.assertTrue(case['verified'])
    def test_unexpected_create_ID_stays_uncertain(self):
        case,holder,writes=self.fixture();api=FakeApi([(202,{'templateID':ID,'buildID':'bad'})])
        with self.assertRaisesRegex(RuntimeError,'identity'):m.build_case(case,holder,api,Path('/owned'),{})
        self.assertEqual(case['state'],'CREATE_INTENT')
    def test_stopped_unknown_status_never_delete(self):
        case,holder,writes=self.fixture('BUILDING');api=FakeApi([(200,{'status':'other'})])
        with self.assertRaisesRegex(RuntimeError,'Unknown'):m.build_case(case,holder,api,Path('/owned'),{})
        self.assertTrue(all(v[0]!='DELETE' for v in api.calls))
    def test_compressed_budget_checked(self):
        descriptor=lambda size:{'digest':'sha256:'+'1'*64,'size':size}
        self.assertEqual(m.descriptors({'config':descriptor(1),'layers':[descriptor(10)]}),11)
        with self.assertRaisesRegex(RuntimeError,'budget'):m.descriptors({'config':descriptor(1),'layers':[descriptor(m.MAX_IMAGE)]})
    def test_bad_descriptor_rejected(self):
        with self.assertRaises(RuntimeError):m.descriptors({'config':{'digest':'../../x','size':1},'layers':[{}]})
    def test_ready_receipt_not_replay_success(self):
        s=m.summary({'status':'COW55_ALL_TEMPLATES_READY_NO_REPLAY_STARTED','replay_started':False,'cases':[{'state':'READY','instance_id':'example'}]})
        self.assertEqual(s['completed_templates'],1);self.assertFalse(s['replay_started'])
    def test_single_manifest_pin_from_exact_bytes(self):
        raw=json.dumps({'config':{'digest':'sha256:'+'1'*64,'size':3},'layers':[{'digest':'sha256:'+'2'*64,'size':4}]}).encode()
        case={'image_tag':'registry/repo:tag'}
        helper=types.SimpleNamespace(checked_process=lambda *a:None,read=lambda *a:raw)
        with patch.object(m,'H',helper):m.resolve(case,Path('/owned'),{})
        self.assertEqual(case['compressed_bytes'],7);self.assertEqual(case['manifest_digest'],'sha256:'+m.sha(raw))
        self.assertEqual(case['pinned_image'],'registry/repo@sha256:'+m.sha(raw))
    def test_ambiguous_platform_index_stops(self):
        row={'digest':'sha256:'+'1'*64,'platform':{'os':'linux','architecture':'arm64'}}
        raw=json.dumps({'manifests':[row,row]}).encode()
        with patch.object(m,'H',types.SimpleNamespace(checked_process=lambda *a:None,read=lambda *a:raw)):
            with self.assertRaisesRegex(RuntimeError,'Ambiguous'):m.resolve({'image_tag':'registry/repo:tag'},Path('/owned'),{})

class ReadyInventoryTests(unittest.TestCase):
    def setup_inventory(self,mode='ok'):
        repo=m.BASE/'state/snapshot-store/repository'
        layer=lambda n:{'digest':'sha256:'+format(n,'064x'),'size':1024}
        record={'id':ID,'resources':{'cpu_count':2,'memory_mib':4096,'disk_size_mib':65536},
                'committed':{'memory_layers':[layer(1)],'rootfs_layers':[{'Managed':layer(n)} for n in range(2,10)]}}
        if mode=='external':record['committed']['rootfs_layers'][0]={'External':layer(2)}
        raw=json.dumps(record).encode();reads=[];stats=[]
        def read(path,*args):
            reads.append(path)
            if path==repo/'catalog/records'/(ID+'.json'):return raw
            if path==repo/'snapshots'/ID/'commit':return b'committed'
            raise FileNotFoundError('Unexpected path: '+str(path))
        def safe(path):
            if not path.is_relative_to(repo/'managed-layers'):raise AssertionError('Wrong layer root')
            return path
        def observe(path,*args,**kwargs):
            stats.append(path)
            if mode=='missing':raise FileNotFoundError(2,'Missing fixture layer',str(path))
            if mode=='denied':raise PermissionError(13,'Unreadable fixture layer',str(path))
            return types.SimpleNamespace(st_mode=stat.S_IFDIR if mode=='directory' else stat.S_IFREG,
                st_size=512 if mode=='size' else 1024,st_blocks=8,st_dev=1,st_ino=len(stats),st_mtime_ns=123)
        def legacy(sid):raise AssertionError('Pinned legacy helper uses the old root; must not be called')
        stack=contextlib.ExitStack();self.addCleanup(stack.close)
        stack.enter_context(patch.object(m,'H',types.SimpleNamespace(read=read,safe=safe,parent_layer_inventory=legacy)))
        stack.enter_context(patch.object(Path,'stat',observe))
        return {'template_id':ID,'build_id':ID,'state':'BUILDING'},reads,stats
    def test_verified_catalog_reused_correct_root_and_no_legacy_call(self):
        case,reads,stats=self.setup_inventory();m.verify_ready(case)
        self.assertEqual(len(reads),2);self.assertEqual(len(stats),9)
        self.assertEqual(case['resources']['cpu_count'],2)
        self.assertEqual(case['layer_inventory_summary']['memory_layers'],1)
        self.assertEqual(case['layer_inventory_summary']['rootfs_layers'],8)
        self.assertTrue(case['layer_inventory_summary']['available'])
    def test_missing_files_still_block_and_retain_diagnostics(self):
        case,_,_=self.setup_inventory('missing')
        with self.assertRaisesRegex(RuntimeError,'unavailable'):m.verify_ready(case)
        v=case['layer_inventory_summary'];self.assertEqual(v['failed_layer_count'],9)
        self.assertEqual(v['failed_layers'][0]['errno'],2)
    def test_size_mismatch_not_ignored(self):
        case,_,_=self.setup_inventory('size')
        with self.assertRaises(RuntimeError):m.verify_ready(case)
        r=case['layer_inventory_summary']['failed_layers'][0]
        self.assertEqual(r['file_bytes'],512);self.assertEqual(r['stored_bytes_declared'],1024)
    def test_external_is_not_silently_accepted(self):
        case,_,stats=self.setup_inventory('external')
        with self.assertRaises(RuntimeError):m.verify_ready(case)
        self.assertEqual(case['layer_inventory_summary']['failed_layer_count'],1)
        self.assertEqual(len(stats),8)
    def test_non_regular_file_rejected(self):
        case,_,_=self.setup_inventory('directory')
        with self.assertRaises(RuntimeError):m.verify_ready(case)
        self.assertEqual(case['layer_inventory_summary']['failed_layer_count'],9)
    def test_unreadable_files_keep_errno(self):
        case,_,_=self.setup_inventory('denied')
        with self.assertRaises(RuntimeError):m.verify_ready(case)
        self.assertEqual(case['layer_inventory_summary']['failed_layers'][0]['errno'],13)
    def test_resume_first_ready_build_needs_no_new_post(self):
        case,_,_=self.setup_inventory();api=FakeApi([(200,{'status':'ready'})]);writes=[]
        with patch.object(m,'save',lambda s:writes.append(copy.deepcopy(s))),patch.object(m,'empty',lambda a:None):
            m.build_case(case,{'cases':[case]},api,Path('/unused'),{})
        self.assertEqual(case['state'],'READY');self.assertEqual([c[0] for c in api.calls],['GET'])
        self.assertTrue(writes[-1]['cases'][0]['layer_inventory_summary']['available'])

if __name__=='__main__':unittest.main()
