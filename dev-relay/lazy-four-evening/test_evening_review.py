import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('evening_review',Path(__file__).with_name('evening_review.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class ReviewTests(unittest.TestCase):
    def test_drop_is_observation_not_invented_cause(self):
        samples=[]
        for i,resident in enumerate((500*1024**2,8192)):
            samples.append({'phase':'replay_window','startNs':i*10,'endNs':i*10+1,
                'lower':{'available':True,'residentBytes':resident},'host':{'memoryBytes':{'Cached':resident+1234}}})
        result=m.summarize({'rootfsCheckpoints':samples})
        self.assertEqual(len(result['largeResidencyDrops']),1)
        self.assertFalse(result['largeResidencyDrops'][0]['causeEstablished'])
        self.assertFalse(result['oldBaselineComparabilityEstablished'])

    def test_missing_reading_does_not_become_zero(self):
        result=m.summarize({'rootfsCheckpoints':[{'phase':'replay_window'}]})
        self.assertIsNone(result['curves'][0]['lowerResidentBytes'])
        self.assertEqual(result['largeResidencyDrops'],[])


if __name__=='__main__':unittest.main()
