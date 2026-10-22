import importlib.util, struct, unittest
from pathlib import Path

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('inspect_cache',HERE/'cache_prefetch_inspect.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class InspectTests(unittest.TestCase):
    def test_crc32c_reference_vector(self):self.assertEqual(m.crc32c(b'123456789'),0xe3069283)
    def test_persisted_header_not_reported_as_live_hit_rate(self):
        raw=struct.pack('<II6Q',0x4f424348,1,1048576,262144,123,5,3,2)+struct.pack('<I',3)+b'key'+b'bitmap-not-decoded'
        raw+=struct.pack('<I',m.crc32c(raw))
        r=m.metadata_header(raw);self.assertEqual((r['hits'],r['misses'],r['refills']),(5,3,2))
        self.assertFalse(r['bitmap_cardinality_decoded']);self.assertNotIn('hit_rate',r)
        with self.assertRaisesRegex(RuntimeError,'checksum'):m.metadata_header(raw[:-1]+bytes([raw[-1]^1]))
    def test_smaller_group_reduces_envelope_not_proven_refill(self):
        pages={(1,2,0),(1,2,1)};files={(1,2):{'file_bytes':1048576}}
        small=m.footprint(pages,files,131072);large=m.footprint(pages,files,262144)
        self.assertEqual(small['touched_cell_capacity_bytes'],131072)
        self.assertEqual(large['touched_cell_capacity_bytes'],262144)
        self.assertIsNone(small['actual_hit_rate']);self.assertIsNone(small['actual_prefetch_efficiency'])
    def test_boundary_can_remove_apparent_saving(self):
        pages={(1,2,31),(1,2,32)};files={(1,2):{'file_bytes':1048576}}
        self.assertEqual(m.footprint(pages,files,131072)['touched_cell_capacity_bytes'],m.footprint(pages,files,262144)['touched_cell_capacity_bytes'])
    def test_tail_rounded_to_existing_file_page_span(self):
        r=m.footprint({(1,2,64)},{(1,2):{'file_bytes':262145}},262144)
        self.assertEqual(r['touched_cell_capacity_bytes'],4096)
    def test_distinct_inodes_not_deduplicated(self):
        r=m.footprint({(1,2,0),(1,3,0)},{(1,2):{'file_bytes':262144},(1,3):{'file_bytes':262144}},262144)
        self.assertEqual(r['distinct_cells_touched'],2)
    def test_no_cache_mutation_or_unknown_cli_execution(self):
        s=(HERE/'cache_prefetch_inspect.py').read_text()
        for forbidden in ('subprocess.','os.posix_fadvise','drop_caches','shutil.rmtree','.unlink(','.mkdir(','.write_text(','.write_bytes('):self.assertNotIn(forbidden,s)


if __name__=='__main__':unittest.main()
