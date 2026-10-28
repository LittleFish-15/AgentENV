"""State/wire/DAX-FD models only; these do not attest UB hardware sharing."""
from concurrent.futures import ThreadPoolExecutor
import copy,hashlib,io,os,tempfile,threading,time,types,unittest
from pathlib import Path
from unittest import mock
from aenv_ub_provider import demand_source as source, host_dax_demand as d, stored


class MemorySource:
    def __init__(self,data):self.data=data;self.size=len(data);self.reads=[]
    def read(self,offset,count):self.reads.append((offset,count));return self.data[offset:offset+count]


class Backend:
    def __init__(self):self.fills=[];self.retires=[];self.fail=False;self.coverage=128*d.MIB;self.release_nodes=None
    def publish(self,manifest,chunk,generation,name):
        self.fills.append(chunk.index)
        if self.fail:raise TimeoutError('publication outcome unknown')
        return {'objectName':name,'generation':generation,'chunkSha256':chunk.sha256,
                'payloadBytes':chunk.length,'chargedCoverageBytes':self.coverage,
                'immutable':True,'source':'obmm-host-fsdax'}
    def retire(self,publication,nodes):
        self.retires.append(nodes)
        return {'objectName':publication['objectName'],'generation':publication['generation'],
                'releasedNodes':list(nodes) if self.release_nodes is None else self.release_nodes,
                'globalDeleteAcknowledged':True}


class DemandTests(unittest.TestCase):
    def setUp(self):
        self.data=bytes((i+i//4096)%256 for i in range(10240))
        self.source=MemorySource(self.data)
        doc,pin=source.build_manifest(self.source,4096)
        self.manifest=d.Manifest(doc,pin)
        self.backend=Backend();self.journal=[]
        self.cache=d.DemandCache(self.backend,lambda value:self.journal.append(copy.deepcopy(value)),
                                 nodes=['a','b'],budget_bytes=256*d.MIB)

    def test_manifest_holes_and_wrong_anchor_rejected(self):
        doc,pin=source.build_manifest(self.source,4096)
        with self.assertRaises(ValueError):d.Manifest(doc,'0'*64)
        doc['chunks'][1]['offset']+=4096
        pin=hashlib.sha256(d.canonical(doc)).hexdigest()
        with self.assertRaises(ValueError):d.Manifest(doc,pin)

    @unittest.skipUnless(hasattr(os,'O_DIRECT') and hasattr(os,'preadv'),'Native Linux O_DIRECT unavailable')
    def test_native_direct_source_reads_unaligned_tail_without_buffered_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'source.bin';path.write_bytes(self.data)
            reader=source.DirectSource(path.resolve(),len(self.data))
            try:
                self.assertEqual(reader.read(4090,40),self.data[4090:4130])
                self.assertEqual(reader.read(len(self.data)-17,17),self.data[-17:])
            finally:reader.close()

    def test_source_copy_loads_only_selected_chunk_and_refuses_overwrite(self):
        self.source.reads=[];out=io.BytesIO()
        result=source.copy_verified_chunk(self.source,self.manifest.chunks[1],out)
        self.assertEqual(out.getvalue(),self.data[4096:8192])
        self.assertEqual(self.source.reads,[(4096,4096)])
        self.assertFalse(result['UBAllocated'])
        with self.assertRaises(ValueError):source.copy_verified_chunk(self.source,self.manifest.chunks[0],io.BytesIO(b'keep'))

    def test_two_nodes_share_one_chunk_publication(self):
        a=self.cache.acquire(self.manifest,self.manifest.chunks[0],'a')
        b=self.cache.acquire(self.manifest,self.manifest.chunks[0],'b')
        self.assertEqual(a.generation,b.generation);self.assertEqual(self.backend.fills,[0])
        self.assertEqual(self.cache.snapshot()['chargedBytes'],128*d.MIB)
        self.assertIsNone(self.cache.snapshot()['stats']['physicalIncrementBytes'])
        with self.assertRaises(d.CacheFull):self.cache.retire_idle()
        self.cache.release(a);self.cache.release(b);self.cache.retire_idle()
        self.assertEqual(self.backend.retires,[('a','b')]);self.assertEqual(self.cache.snapshot()['chargedBytes'],0)

    def test_concurrent_misses_coalesce(self):
        entered=threading.Event();proceed=threading.Event();real=self.backend.publish
        def publish(*args):entered.set();self.assertTrue(proceed.wait(3));return real(*args)
        self.backend.publish=publish
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures=[pool.submit(self.cache.acquire,self.manifest,self.manifest.chunks[0],node) for node in ('a','b','a','b')]
            self.assertTrue(entered.wait(2));proceed.set();tickets=[f.result(timeout=3) for f in futures]
        self.assertEqual(len({t.generation for t in tickets}),1);self.assertEqual(self.backend.fills,[0])
        for t in tickets:self.cache.release(t)

    def test_unknown_publish_is_not_retried_or_freed(self):
        self.backend.fail=True
        with self.assertRaises(TimeoutError):self.cache.acquire(self.manifest,self.manifest.chunks[0],'a')
        with self.assertRaises(RuntimeError):self.cache.acquire(self.manifest,self.manifest.chunks[0],'b')
        self.assertEqual(self.backend.fills,[0]);self.assertEqual(self.cache.snapshot()['chargedBytes'],128*d.MIB)
        with self.assertRaises(d.CacheFull):self.cache.retire_idle()

    def test_capacity_exhaustion_does_not_create_or_evict_pinned_data(self):
        tickets=[self.cache.acquire(self.manifest,c,'a') for c in self.manifest.chunks[:2]]
        with self.assertRaises(d.CacheFull):self.cache.acquire(self.manifest,self.manifest.chunks[2],'b')
        self.assertEqual(self.backend.fills,[0,1])
        self.cache.release(tickets[0]);self.cache.retire_idle()
        self.cache.acquire(self.manifest,self.manifest.chunks[2],'b')
        self.assertEqual(self.backend.fills,[0,1,2])

    def test_missing_peer_receipt_retains_uncertain_capacity(self):
        a=self.cache.acquire(self.manifest,self.manifest.chunks[0],'a');b=self.cache.acquire(self.manifest,self.manifest.chunks[0],'b')
        self.cache.release(a);self.cache.release(b);self.backend.release_nodes=['a']
        with self.assertRaises(ValueError):self.cache.retire_idle()
        self.assertEqual(self.cache.snapshot()['entries'][0]['phase'],'UNCERTAIN')
        self.assertEqual(self.cache.snapshot()['chargedBytes'],128*d.MIB)

    def test_stale_ticket_cannot_release_new_generation(self):
        first=self.cache.acquire(self.manifest,self.manifest.chunks[0],'a');self.cache.release(first);self.cache.retire_idle()
        second=self.cache.acquire(self.manifest,self.manifest.chunks[0],'a')
        self.assertNotEqual(first.generation,second.generation)
        with self.assertRaises(ValueError):self.cache.release(first)

    def test_post_map_coverage_overshoot_is_reported_not_hidden(self):
        self.backend.coverage=256*d.MIB
        with self.assertRaises(ValueError):self.cache.acquire(self.manifest,self.manifest.chunks[0],'a')
        self.assertEqual(self.cache.snapshot()['chargedBytes'],256*d.MIB)
        with self.assertRaises(d.CacheFull):self.cache.acquire(self.manifest,self.manifest.chunks[1],'a')

    def test_journal_failure_blocks_further_allocation(self):
        def failed_save(value):raise OSError('disk failure')
        self.cache.save=failed_save
        with self.assertRaises(OSError):self.cache.acquire(self.manifest,self.manifest.chunks[0],'a')
        with self.assertRaises(RuntimeError):self.cache.acquire(self.manifest,self.manifest.chunks[1],'a')
        self.assertEqual(self.backend.fills,[])

    def test_existing_journal_never_implicitly_resumes(self):
        with self.assertRaises(ValueError):d.DemandCache(self.backend,lambda _:None,nodes=['a'],budget_bytes=128*d.MIB,prior_state={})

    def mapping(self,validator):
        replica=stored.Replica(str((Path(tempfile.gettempdir())/'demand.sock').resolve()),'aenv_'+'1'*32,'2'*32,
            self.manifest.layer_digest,self.manifest.file_bytes,stored.ALIGN)
        views={};fds={};next_fd=iter(range(50,100))
        def factory(publication,node):
            chunk=next(c for c in self.manifest.chunks if c.sha256==publication['chunkSha256'])
            fd=next(next_fd);fds[fd]=self.data[chunk.offset:chunk.offset+chunk.length]
            view=types.SimpleNamespace(fd=fd,device=7,close=mock.Mock());views[chunk.index]=view;return view
        def pread(fd,count,offset):return fds[fd][offset:offset+count]
        mapper=d.DemandDaxMapping(replica,self.manifest,self.cache,'a',factory)
        return mapper,views,pread

    def test_wire_header_does_not_prefill_and_cross_chunk_reads_are_exact(self):
        mapper,views,pread=self.mapping(None)
        with mock.patch.object(d.fsdax,'validate_fd',return_value={'device':7}), \
             mock.patch.object(d,'os',types.SimpleNamespace(pread=pread)):
            self.assertEqual(mapper.read(0,stored.HEADER.size),mapper.replica.header())
            self.assertEqual(self.backend.fills,[])
            self.assertEqual(mapper.read(stored.HEADER_BYTES+4090,20),self.data[4090:4110])
            self.assertEqual(self.backend.fills,[0,1])
            self.assertEqual(mapper.read(stored.HEADER_BYTES+20,10),self.data[20:30])
            self.assertEqual(self.backend.fills,[0,1])
            self.assertTrue(all(not e['pins'] for e in self.cache.snapshot()['entries']))
            mapper.close()

    def test_non_dax_fd_never_serves_bytes_and_preserves_read_ticket(self):
        mapper,views,pread=self.mapping(None)
        with mock.patch.object(d.fsdax,'validate_fd',side_effect=ValueError('not DAX')), \
             mock.patch.object(d,'os',types.SimpleNamespace(pread=mock.Mock())):
            with self.assertRaises(ValueError):mapper.read(stored.HEADER_BYTES,10)
            d.os.pread.assert_not_called()
        self.assertEqual(len(mapper.failed_tickets),1)
        with self.assertRaises(ValueError):mapper.close()


if __name__=='__main__':unittest.main()
