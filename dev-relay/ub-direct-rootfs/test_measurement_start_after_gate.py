import importlib.util,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('start',Path(__file__).with_name('B_start_measurement_after_gate_v1.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class StartGuards(unittest.TestCase):
 def markers(self):return {k:False for k in ('fullReceipt','originalReceipt','lock','run','originalDirectory','failureOriginal','failureFull')}
 def test_only_unattempted_can_start(self):self.assertEqual(m.decide(self.markers()),'start-original')
 def test_any_durable_attempt_blocks_restart(self):
  for key in ('lock','run','originalDirectory','failureOriginal','failureFull'):
   marks=self.markers();marks[key]=True;self.assertEqual(m.decide(marks),'existing-attempt-no-restart')
 def test_completed_original_is_not_rerun(self):
  marks=self.markers();marks.update(originalReceipt=True,run=True,originalDirectory=True)
  self.assertEqual(m.decide(marks),'original-completed')
 def test_completed_both_is_not_rerun(self):
  marks=self.markers();marks.update(fullReceipt=True,originalReceipt=True)
  self.assertEqual(m.decide(marks),'local-both-completed')
if __name__=='__main__':unittest.main()
