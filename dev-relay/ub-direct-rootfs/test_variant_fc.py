import hashlib,importlib.util,unittest
from pathlib import Path
HERE=Path(__file__).parent
spec=importlib.util.spec_from_file_location('fc_gate',HERE/'variant_fc_admission.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class FC(unittest.TestCase):
    def test_each_exact_variant_accepted(self):
        for variant,row in m.FC_BUILDS.items():self.assertEqual(m.validate_fc(variant,row['sha256'],row['bytes']),row)
    def test_wrong_variant_or_unknown_binary_rejected(self):
        for variant in m.FC_BUILDS:
            other=m.FC_BUILDS['original' if variant=='full' else 'full']
            with self.assertRaises(ValueError):m.validate_fc(variant,other['sha256'],other['bytes'])
            with self.assertRaises(ValueError):m.validate_fc(variant,'0'*64,m.FC_BUILDS[variant]['bytes'])
    def test_size_mismatch_and_boolean_rejected(self):
        for variant,row in m.FC_BUILDS.items():
            for size in (row['bytes']+1,True):
                with self.assertRaises(ValueError):m.validate_fc(variant,row['sha256'],size)
    def test_aggregation_explicitly_carries_variant_caveat(self):
        source=(HERE/'variant_fc_aggregation_body.py').read_text()
        self.assertIn("'UBOnlyCausalAttribution':False",source)
        self.assertIn("modules['admission'].validate_fc(variant,context['firecrackerSha256'],context['firecrackerBytes'])",source)
if __name__=='__main__':unittest.main()
