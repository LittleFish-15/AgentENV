import ast
import importlib.util
import json
from pathlib import Path
import types
import unittest
from unittest import mock

spec=importlib.util.spec_from_file_location('readback',Path(__file__).with_name('lazy_four_readback.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class Readback(unittest.TestCase):
    def test_partial_replay_is_not_reported_as_complete_comparison(self):
        report={'node':'node-a','scenario':'lazy','status':'STOPPED_LAZY_FOUR_PRESERVE_JOURNAL',
                'ownedGuestsReleased':True,'outcomeUncertain':False,
                'jobs':[{'index':0,'state':'REPLAY_FAILED','stepsCompleted':17,'failedCommands':1}],
                'rootfsCheckpoints':[{'phase':'replay_window','lower':{'available':True,'residentBytes':0,'files':[]}}]}
        result=m.report_summary(report)
        self.assertFalse(result['fullComparisonAccepted'])
        self.assertEqual(result['actionsCompleted'],17)
        self.assertEqual(result['completedGuests'],0)
        self.assertIsNone(result['completed'])
        self.assertEqual(result['lastRootfsCheckpoint']['lowerResidentBytes'],0)

    def test_missing_measurements_are_not_zero(self):
        self.assertIsNone(m.checkpoint(None))
        self.assertIsNone(m.checkpoint({'phase':'replay_window'})['lowerResidentBytes'])
        self.assertIsNone(m.report_summary({})['sampleCount'])

    def test_redaction_and_readonly_remote_source(self):
        self.assertNotIn('secretvalue',m.redact('"token": "secretvalue"'))
        self.assertNotIn('e2b_abcdef',m.redact('e2b_abcdef'))
        result=types.SimpleNamespace(returncode=0,stdout=b'{"node":"node-b"}')
        with mock.patch.object(m.subprocess,'run',return_value=result) as run:
            self.assertEqual(m.remote_read(),{'node':'node-b'})
        import shlex
        remote_args=shlex.split(run.call_args.args[0][-1])
        self.assertEqual(remote_args[:4],['/usr/bin/python3','-I','-B','-c'])
        code=remote_args[4];ast.parse(code)
        self.assertNotIn('systemctl',code)
        self.assertNotIn('posix_fadvise',code)
        self.assertNotIn('NativeBackend',code)
        self.assertNotIn('write_text',code)


if __name__=='__main__':unittest.main()
