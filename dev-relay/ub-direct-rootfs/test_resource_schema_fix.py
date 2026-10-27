"""Resource-contract regression tests; no target or UB hardware execution."""
import ast,base64,copy,hashlib,json,sys,types,unittest,zlib
from pathlib import Path
HERE=Path(__file__).parent
if sys.platform=='win32':sys.modules.setdefault('fcntl',types.ModuleType('fcntl'))

def load(file):
    m=types.ModuleType(file);m.__file__=str(HERE/file)
    exec(compile((HERE/file).read_bytes(),m.__file__,'exec'),m.__dict__)
    return m

comp=load('AB_deletefix_local_comparison_v2.py')
gate=comp.module('admission');cohort=comp.module('cohort');replay=comp.module('native_replay')
aggregate=load('aggregate_deletefix_comparison_v2.py')
RES={'cpu_count':2,'memory_mib':4096,'disk_size_mib':10240}

class ResourceSchema(unittest.TestCase):
    def row(self):return {'templateId':'template','templateIndex':0,'catalogSha256':'a'*64,'replaySha256':'b'*64,
        'resources':dict(RES),'rootfsLayers':[{'digest':'sha256:'+'c'*64,'size':4096}]}
    def test_real_serde_schema_not_two_field_fixture(self):
        self.assertEqual(gate.input_signature([self.row()])[0][3],RES)
        for m in (gate,cohort,replay):self.assertTrue(m.valid_resources(RES))
    def test_wrong_or_missing_values_rejected_at_all_layers(self):
        bad=[{k:v for k,v in RES.items() if k!='disk_size_mib'},
             {**RES,'cpu_count':4},{**RES,'memory_mib':2048},{**RES,'disk_size_mib':0},
             {**RES,'disk_size_mib':True},{**RES,'disk_size_mib':2**32},
             {**RES,'disk_size_mib':'10240'},{**RES,'unexpected':1}]
        for value in bad:
            for m in (gate,cohort,replay):self.assertFalse(m.valid_resources(value))
            row=self.row();row['resources']=value
            with self.assertRaises(ValueError):gate.input_signature([row])
    def test_full_disk_value_is_part_of_input_comparison(self):
        left=self.row();right=copy.deepcopy(left);right['resources']['disk_size_mib']+=1
        semantics={'guestTimeoutSeconds':300,'cliTimeoutSeconds':330,'terminalActionPolicy':'stop_before_submit_finish_done',
                   'nonzeroPolicy':'record_each_and_compare','globalCacheEviction':False}
        gate.matching_inputs([left],[left],semantics)
        with self.assertRaisesRegex(ValueError,'inputs differ'):gate.matching_inputs([left],[right],semantics)
    def jobs(self):
        return [{**self.row(),'slot':i,'sandboxId':'guest-'+str(i),'lowerContentSha256':'c'*64,
                 'steps':[{'action':'true','delay':0}]} for i in range(2)]
    def test_replay_accepts_actual_resource_schema(self):
        runner=replay.NativeGroupReplay(Path('unused'),Path('/pinned/aenv'),{},self.jobs(),None,None,None,None)
        self.assertEqual(runner.state['jobs'][0]['resources'],RES)
        self.assertEqual(runner.state['GuestTimeoutSeconds'],300)
        self.assertEqual(runner.state['CLITransportTimeoutSeconds'],330)
    def test_disk_changes_workload_signature(self):
        a=self.jobs();b=copy.deepcopy(a);b[0]['resources']['disk_size_mib']+=1
        self.assertNotEqual(replay.workload_signature(a),replay.workload_signature(b))
    def test_cohort_admits_three_fields_before_mutation(self):
        permit=types.SimpleNamespace(check=lambda *args:None)
        obj=cohort.ActualComparisonCohort(None,None,None,None,None,Path('/unused'),'original',[self.row()],{},None,None,permit=permit)
        self.assertEqual(obj.templates[0]['resources'],RES)
        self.assertEqual(obj.cases,{})
    def test_aggregate_checks_complete_job_resources(self):
        tree=ast.parse((HERE/'resourcefix_aggregation_body.py').read_text())
        predicates=[n.args[0] for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name)
                    and n.func.id=='need' and len(n.args)>1 and isinstance(n.args[1],ast.Constant) and n.args[1].value=='Resources differ']
        self.assertEqual(len(predicates),1)
        expr=compile(ast.Expression(predicates[0]),'<actual-aggregate-resource-predicate>','eval')
        self.assertTrue(eval(expr,{'job':{'resources':RES},'signature':[None,None,None,RES]}))
        self.assertFalse(eval(expr,{'job':{'resources':{**RES,'disk_size_mib':1}},'signature':[None,None,None,RES]}))
    def test_embedded_pins_and_unchanged_lifecycle_sampler(self):
        old=load('AB_deletefix_local_comparison_v1.py')
        for key in ('ready','continue_pair','inputs','sampler','ram','journal','pair_verify','lower_views'):
            self.assertEqual(comp.MODULES[key],old.MODULES[key])
        self.assertEqual(aggregate.CONTROLLER,hashlib.sha256((HERE/'AB_deletefix_local_comparison_v2.py').read_bytes()).hexdigest())
        self.assertEqual(comp.PAIR_SHA,old.PAIR_SHA)
        self.assertEqual(aggregate.dependency('admission').input_signature([self.row()])[0][3],RES)

if __name__=='__main__':unittest.main()
