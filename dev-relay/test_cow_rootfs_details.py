import importlib.util,unittest
from pathlib import Path

spec=importlib.util.spec_from_file_location('details',Path(__file__).with_name('cow_rootfs_details.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class Details(unittest.TestCase):
    def part(self,inode,size=10000,allocated=4096,cached=8192):
        return {'available':True,'dev':1,'inode':inode,'logical_file_or_device_bytes':size,'allocated_file_bytes':allocated,'resident_page_bytes':cached}
    def row(self):
        return {'template_id':'t','phase':'both_replaying','sandbox_ids':['a','b'],
                'upper_observations':[{'sandbox_id':'a','files':[self.part(1),self.part(2)]},{'sandbox_id':'b','files':[self.part(3),self.part(4)]}]}
    def test_keeps_length_allocation_and_residency_distinct(self):
        r=m.expand_row(self.row());self.assertEqual(r['sandbox1_upper_file_bytes'],20000)
        self.assertEqual(r['sandbox1_upper_allocated_bytes'],8192);self.assertEqual(r['sandbox1_upper_resident_bytes'],16384)
    def test_missing_component_is_na_not_zero(self):
        r=self.row();r['upper_observations'][0]['files'][1]={'available':False}
        v=m.expand_row(r);self.assertIsNone(v['sandbox1_upper_allocated_bytes']);self.assertEqual(v['sandbox2_upper_allocated_bytes'],8192)
    def test_duplicate_file_identity_not_double_counted(self):
        r=self.row();r['upper_observations'][0]['files']=[self.part(1),self.part(1)]
        self.assertEqual(m.expand_row(r)['sandbox1_upper_allocated_bytes'],4096)
    def test_no_samples_preserves_lower_but_not_invent_upper(self):
        report={'run_id':'r','status':'failed','jobs':[{'template_id':'t','instance_id':'fixture','sandbox_id':s} for s in ('a','b')],
                'template_lowers':{'t':[{'dev':1,'inode':10,'file_bytes':12345}]}}
        r=m.summarize(report,[]);self.assertEqual(r['rows'][0]['lower_file_bytes'],12345)
        self.assertEqual(r['rows'][0]['metrics'],{});self.assertIn('NA',m.markdown(r))
    def test_upper_ranges_survive_summary_and_markdown(self):
        report={'run_id':'r','jobs':[{'template_id':'t','instance_id':'fixture','sandbox_id':s} for s in ('a','b')],
                'template_lowers':{'t':[{'dev':1,'inode':10,'file_bytes':12345}]}}
        a=self.row();b=self.row();b['upper_observations'][0]['files'][0]['allocated_file_bytes']=12288
        r=m.summarize(report,[{'templates':[a]},{'templates':[b]}]);metric=r['rows'][0]['metrics']['sandbox1_upper_allocated_bytes']
        self.assertEqual(metric,{'min':8192,'max':16384,'valid_samples':2});self.assertIn('S1 upper分配',m.markdown(r))


if __name__=='__main__':unittest.main()
