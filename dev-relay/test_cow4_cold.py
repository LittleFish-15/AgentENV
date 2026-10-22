import contextlib, importlib.util, json, unittest, uuid
from pathlib import Path
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('cold_packet',HERE/'cow4_cold_once.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
c=p.COLD


@contextlib.contextmanager
def test_directory():
    directory=HERE/('.cold-test-'+uuid.uuid4().hex)
    directory.mkdir(mode=0o777) # Inherited Windows test ACL; production remains 0700.
    try:yield directory
    finally:
        for name in ('r.json','cross.json'):
            file=directory/name
            if file.exists():file.unlink()
        directory.rmdir()


class ColdTests(unittest.TestCase):
    def test_same_256k_cell_different_4k_pages_is_not_shared_page(self):
        a={(1,2,0)};b={(1,2,63)};resident=a|b;files={(1,2):{'file_bytes':262144}}
        exact=p.ACCOUNTING.pair_statistics(a,b,resident)
        coarse=c.coarse_comparison(a,b,resident,files)
        self.assertEqual(exact['shared_accessed_host_pagecache_bytes'],0)
        self.assertEqual(coarse['coarse_256k_common_cell_capacity_upper_bound_bytes'],262144)

    def test_256k_partial_cells_preserve_exact_page_count(self):
        bits=bytearray([1]*64+[1,0,1]+[0]*61+[1])
        v=c.vector_counts(bits)
        self.assertEqual(v['resident_bytes'],67*4096)
        self.assertEqual(v['resident_bytes_summed_inside_256k_cells'],67*4096)
        self.assertEqual(v['cells_256k_partly_resident'],1)
        self.assertEqual(v['cells_256k_fully_resident'],2)
        self.assertEqual(v['any_resident_cell_capacity_upper_bound_bytes'],129*4096)

    def test_coarse_tail_is_clipped_to_page_span(self):
        pages={(1,2,64)}
        v=c.coarse_comparison(pages,pages,pages,{(1,2):{'file_bytes':262145}})
        self.assertEqual(v['coarse_256k_common_cell_capacity_upper_bound_bytes'],4096)

    def test_cold_failure_saved_and_not_accepted(self):
        with test_directory() as d:
            path=Path(d)/'r.json'
            with patch.object(c,'scan',side_effect=[(set(),{'whole_lower_resident_bytes':8192}),(set(),{'whole_lower_resident_bytes':4096})]),patch.object(c,'evict') as evict:
                with self.assertRaisesRegex(RuntimeError,'left resident'):c.cold_checkpoint({},path,'test')
                evict.assert_called_once()
            self.assertFalse(json.loads(path.read_text())['zero_resident_at_each_file_observation'])

    def test_cold_success_requires_observed_zero(self):
        with test_directory() as d:
            with patch.object(c,'scan',side_effect=[(set(),{'whole_lower_resident_bytes':8192}),(set(),{'whole_lower_resident_bytes':0})]),patch.object(c,'evict'):
                r=c.cold_checkpoint({},Path(d)/'r.json','test')
            self.assertTrue(r['zero_resident_at_each_file_observation'])
            self.assertFalse(r['globally_atomic_cold_state_claimed'])

    def test_whole_and_attributed_are_from_same_bitmap(self):
        c.TEMPLATE_KEYS={'t':{(1,2)}}
        a={(1,2,0)};b={(1,2,1)};res=a|b
        row=dict(p.ACCOUNTING.pair_statistics(a,b,res),template_id='t',sandbox_ids=['a','b'],lower_page_span_bytes=4*4096)
        frame={'templates':[row],'residency_probe':{'whole_lower_files':[{'dev':1,'inode':2,'resident_bytes':3*4096}]}}
        c.enrich(frame,{(1,2):{'file_bytes':4*4096}},{'a':a,'b':b},res)
        self.assertEqual(row['lower_resident_outside_pair_observed_access_bytes'],4096)
        self.assertEqual(row['whole_lower_residency_fraction'],.75)

    def test_no_global_cache_drop_or_kernel_changes(self):
        code=p._source('cold')
        self.assertNotIn('/proc/sys/vm/drop_caches',code)
        self.assertNotIn('os.sync(',code)
        self.assertNotIn('modprobe',code)
        self.assertNotIn('os.pwrite',code)
        self.assertEqual(code.count('os.pread('),1) # Only owned fixture.

    def test_isolated_pending_and_exact_old_binary(self):
        code=(HERE/'cow4_cold_once.py').read_text(encoding='utf-8')
        self.assertIn("m.PENDING=m.ROOT/'relay/cow4-cold-node-a.pending.json'",code)
        self.assertEqual(p.CANDIDATE_SHA,'eed36d01de13f83a8abdc13e93c21883a3a48273da83fa1c813e65e4655babcf')
        self.assertIs(p.ACCOUNTING.resident_accessed_pages,c.scan)
        self.assertIn("endpoint.name=='c4-'",p.ROOT_SOURCE)
        self.assertIn("('c4-'+cohort.run_id",code)
        self.assertIn("m.need(not seventeen.exists()",code)

    def test_both_cold_gates_precede_replay(self):
        code=(HERE/'cow4_cold_once.py').read_text(encoding='utf-8')
        start=code.index('    def run(self):')
        body=code[start:code.index('\ndef main():',start)]
        self.assertLess(body.index('cold-before-restore.json'),body.index('c.create(j)'))
        self.assertLess(body.index("self.rpc('bind'"),body.index('cold-before-replay.json'))
        self.assertLess(body.index('cold-before-replay.json'),body.index('self.start=time.monotonic_ns()'))
        self.assertLess(body.index('self.start=time.monotonic_ns()'),body.index('pool.submit(self.replay'))

    def test_crosscheck_unavailable_is_visible(self):
        info={'path':'/owned/file','dev':1,'inode':2,'file_bytes':4096}
        from types import SimpleNamespace
        with test_directory() as d:
            with patch.object(c,'checked_fd',return_value=(9,SimpleNamespace(st_size=4096))),patch.object(c,'vector',return_value=bytearray([1])),patch.object(c.os,'close'),patch.object(c.subprocess,'run',side_effect=FileNotFoundError):
                result=c.independent_check({(1,2):info},Path(d)/'cross.json')
            self.assertEqual(result['available_files'],0)
            self.assertEqual(result['agreeing_files'],0)


if __name__=='__main__':unittest.main()
