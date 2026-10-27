import importlib.util,types,unittest
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
 def test_online_handoff_does_not_overwrite_existing_offline_name(self):
  calls=[];pipeline=types.SimpleNamespace(RUN='r',put=lambda *args:calls.append(args))
  online=types.SimpleNamespace(online_command=lambda *args:'verified command')
  text=m.stage_online(pipeline,online,'original-a','a',{})
  self.assertEqual(calls[0][0].name,'next-measure-online-original-a-r.sh')
  self.assertIn('verified command',text)
if __name__=='__main__':unittest.main()
