import struct
import unittest

from aenv_ub_provider import host_pmem_cache as c


class CacheTests(unittest.TestCase):
    def buffer(self,flags=1,logical=0,physical=4096,size=8192):
        data=bytearray(c.HEADER.size+c.CAPACITY*c.EXTENT.size)
        c.HEADER.pack_into(data,0,0,8192,0,1,c.CAPACITY,0)
        c.EXTENT.pack_into(data,32,logical,physical,size,0,0,flags,0,0,0)
        return data

    def test_exact_extent_mapping_counts_data_separately_from_metadata(self):
        ranges=c.data_ranges(self.buffer(),8192,16384,4096)
        self.assertEqual(ranges,[(4096,8192)])
        result=c.count_residency([1,0,1,1],ranges,4096)
        self.assertEqual(result['blockPageCacheBytes'],12288)
        self.assertEqual(result['fileDataInBlockPageCacheBytes'],4096)
        self.assertEqual(result['otherBlockPageCacheBytes'],8192)

    def test_unknown_encoded_inline_and_unwritten_are_not_zero_cache(self):
        for flags in (0,3,5,9,0x201,0x801):
            with self.assertRaises(ValueError):c.data_ranges(self.buffer(flags=flags),8192,16384,4096)

    def test_sparse_out_of_bounds_and_unaligned_extents_rejected(self):
        for values in ({'logical':4096},{'physical':12288},{'physical':1},{'size':4097}):
            with self.assertRaises(ValueError):c.data_ranges(self.buffer(**values),8192,16384,4096)

    def test_overlapping_physical_ranges_are_not_double_counted(self):
        result=c.count_residency([1,1,0],[(0,8192),(4096,4096)],4096)
        self.assertEqual(result['fileDataInBlockPageCacheBytes'],8192)

    def test_short_buffer_and_residency_overflow_rejected(self):
        with self.assertRaises(ValueError):c.data_ranges(b'',8192,16384,4096)
        with self.assertRaises(ValueError):c.count_residency([0],[(4096,4096)],4096)


if __name__=='__main__':unittest.main()
