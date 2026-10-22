import ast,importlib.util,unittest
from pathlib import Path

spec=importlib.util.spec_from_file_location('preflight',Path(__file__).with_name('cow17_access_preflight.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class Preflight(unittest.TestCase):
    def test_trace_projection_checks_both_independent_limits(self):
        r=m.trace_projection({'records_written':100,'bytes_written':10000},12000,10)
        self.assertEqual(r['projected_records'],1500);self.assertEqual(r['projected_bytes'],180000)
        self.assertTrue(r['projected_within_existing_limits']);self.assertFalse(r['projection_is_a_guarantee'])
        self.assertFalse(m.trace_projection({'records_written':100000,'bytes_written':100},100,10)['projected_within_existing_limits'])
        self.assertFalse(m.trace_projection({'records_written':100,'bytes_written':20000000},20000000,10)['projected_within_existing_limits'])
    def test_empty_trace_is_not_a_zero_cost_projection(self):
        with self.assertRaises(RuntimeError):m.trace_projection({'records_written':0,'bytes_written':10},10,10)
    def test_selects_exact_prior_17_not_first_arbitrary_17(self):
        cases=[{'instance_id':str(i),'recorded_wait_seconds':10} for i in range(55)]
        old={'run_id':'083604f2f76045c0beb8de4cf92c0758','all_cohort_guests_released':True,
            'jobs':[{'index':2*i+s,'instance_id':str(i+20),'state':'REPLAY_COMPLETED','steps_completed':10} for i in range(17) for s in range(2)]}
        four={'jobs':[{'instance_id':str(i+20),'steps_completed':10} for i in range(4) for _ in range(2)]}
        selected,factor=m.selection({'cohort':{'cases':cases}},old,four)
        self.assertEqual([c['instance_id'] for c in selected],[str(i) for i in range(20,37)]);self.assertEqual(factor,17/4)
    def test_no_mutating_service_or_filesystem_calls(self):
        tree=ast.parse(Path(m.__file__).read_text(encoding='utf-8'))
        for node in ast.walk(tree):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute):
                self.assertNotIn(node.func.attr,('unlink','write_text','write_bytes','chmod','chown','mkdir','remove','rename'))
                if isinstance(node.func.value,ast.Name) and node.func.value.id in ('os','shutil'):
                    self.assertNotEqual(node.func.attr,'replace')
        strings=[n.value for n in ast.walk(tree) if isinstance(n,ast.Constant) and isinstance(n.value,str)]
        for value in ('restart','stop','start','modprobe','DELETE','POST','PUT'):self.assertNotIn(value,strings)


if __name__=='__main__':unittest.main()
