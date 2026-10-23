import copy, hashlib, importlib.util, json, stat, struct, sys, types, unittest
from pathlib import Path
from unittest.mock import patch, Mock

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('memory_cache',HERE/'dsec_memory_cache.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def guests():
    return [{'sandboxId':'s'+str(i), 'pid':10+i, 'startTicks':'tick'+str(i),
             'memoryDevice':{'available':True,'path':'/dev/ublkb3','dev':5,'inode':17,'rdev':259,
                             'virtualBytes':4096*1024**2}}
            for i in range(2)]


class FakeDevice:
    def resolve(self,strict=True):return self
    def stat(self):return types.SimpleNamespace(st_mode=stat.S_IFBLK,st_dev=5,st_ino=17,st_rdev=259)


class MemoryCache(unittest.TestCase):
    def test_same_device_two_guests_grouped_once(self):
        groups, missing=m.device_groups(guests())
        self.assertEqual(len(groups),1);self.assertFalse(missing)
        self.assertEqual(len(next(iter(groups.values()))['guests']),2)

    def test_shared_device_different_capacity_rejected(self):
        rows=guests();rows[1]['memoryDevice']['virtualBytes']=512*1024**2
        with self.assertRaisesRegex(RuntimeError,'contract differs'):m.device_groups(rows)

    def test_no_live_guest_does_not_read_old_device_numbers(self):
        with patch.object(m.os,'open') as opened:
            result=m.device_cache([],None)
        opened.assert_not_called();self.assertIsNone(result['uniqueResidentPageBytes'])

    def test_device_named_vma_identity_bound_before_query(self):
        device=FakeDevice();text='1000-2000 rw-p 00000000 00:05 17 /dev/ublkb3\n'
        with patch.object(m,'Path',return_value=device),patch.object(m.os,'major',return_value=0,create=True),\
             patch.object(m.os,'minor',return_value=5,create=True):
            row=m.bind_device('/dev/ublkb3',text,4096*1024**2)
        self.assertTrue(row['available']);self.assertEqual(row['inode'],17)

    def test_replaced_device_inode_rejected_even_same_path(self):
        with patch.object(m,'Path',return_value=FakeDevice()),self.assertRaisesRegex(RuntimeError,'inode differs'):
            m.bind_device('/dev/ublkb3','1000-2000 rw-p 00000000 00:05 18 /dev/ublkb3\n',4096*1024**2)

    def test_device_scope_rejects_other_block_device_before_stat(self):
        with patch.object(m,'Path') as path,self.assertRaisesRegex(RuntimeError,'scoped ublk'):
            m.bind_device('/dev/sda','',4096)
        path.assert_not_called()

    def device_run(self, rows, capacity=4096*1024**2, replace_after=False, stale_pid=False):
        device=FakeDevice();count={}
        def identity(pid):
            count[pid]=count.get(pid,0)+1
            return 1, ('changed' if stale_pid and count[pid]>1 else 'tick'+str(pid-10))
        observer=types.SimpleNamespace(identity=identity,resident_pages=Mock(return_value=42))
        metadata=device.stat();after=copy.copy(metadata)
        if replace_after:after.st_ino=18
        fakefcntl=types.SimpleNamespace(ioctl=Mock(return_value=struct.pack('Q',capacity)))
        with patch.dict(sys.modules,{'fcntl':fakefcntl}),patch.object(m,'Path',return_value=device),\
             patch.object(m.os,'open',return_value=55) as opened,patch.object(m.os,'close'),\
             patch.object(m.os,'fstat',side_effect=[metadata,after]),\
             patch.object(m.os,'sysconf',return_value=4096,create=True),\
             patch.object(m.os,'O_NOFOLLOW',0,create=True),patch.object(m.os,'O_CLOEXEC',0,create=True),\
             patch.object(m.os,'O_NONBLOCK',0,create=True):
            result=m.device_cache(rows,observer)
        return result,opened.call_count,observer.resident_pages

    def test_device_query_deduplicates_and_preserves_overlap_warning(self):
        result,opens,resident=self.device_run(guests())
        self.assertEqual(opens,1);self.assertEqual(resident.call_count,1)
        self.assertTrue(result['available']);self.assertEqual(result['uniqueResidentPageBytes'],42*4096)
        self.assertFalse(result['addToHostCachedOrGuestPss'])

    def test_wrong_device_size_not_mapped(self):
        result,_,resident=self.device_run(guests(),capacity=512*1024**2)
        resident.assert_not_called();self.assertFalse(result['available'])

    def test_device_or_guest_change_discards_value(self):
        for keyword in ('replace_after','stale_pid'):
            result,_,_=self.device_run(guests(),**{keyword:True})
            self.assertFalse(result['available']);self.assertIsNone(result['uniqueResidentPageBytes'])

    def test_partial_guest_binding_not_reported_as_complete_device_total(self):
        rows=guests();rows[1]['memoryDevice']={'available':False}
        result,_,_=self.device_run(rows)
        self.assertFalse(result['available']);self.assertIsNone(result['uniqueResidentPageBytes'])
        self.assertTrue(result['devices'][0]['available'])

    def inventory(self, mutate=None):
        templates,records=[],{}
        for i in range(4):
            sid='00000000-0000-0000-0000-'+str(i).zfill(12)
            record={'id':sid,'resources':{'memory_mib':4096},'committed':{'memory_layers':[
                {'digest':'sha256:'+'a'*64,'size':4096}]}}
            if mutate:mutate(record,i)
            raw=json.dumps(record).encode();records[sid+'.json']=raw
            templates.append({'templateIndex':i,'nativeTemplateId':sid,
                'snapshotEvidence':{'committedRecordSha256':hashlib.sha256(raw).hexdigest()}})
        rt=types.SimpleNamespace(read=lambda path:records[path.name])
        meta=types.SimpleNamespace(st_dev=1,st_ino=1,st_size=4096,st_mtime_ns=2,st_ctime_ns=3,st_uid=1204)
        observer=types.SimpleNamespace(owned_regular=lambda path,limit:meta)
        return rt,observer,templates

    def test_memory_files_deduplicated_from_committed_records(self):
        rt,obs,templates=self.inventory()
        rows=m.memory_lower_inventory(rt,obs,Path('/owned/deployment'),templates)
        self.assertEqual(len(rows),1);self.assertEqual(rows[0]['templateIndices'],[0,1,2,3])
        self.assertEqual(Path(rows[0]['path']).name,'sha256_'+'a'*64+'.overlaybd.commit')

    def test_committed_record_hash_mismatch_not_sampled(self):
        rt,obs,templates=self.inventory();templates[0]['snapshotEvidence']['committedRecordSha256']='0'*64
        with self.assertRaisesRegex(RuntimeError,'record changed'):
            m.memory_lower_inventory(rt,obs,Path('/owned'),templates)

    def test_memory_digest_path_traversal_rejected(self):
        rt,obs,templates=self.inventory(lambda r,i:r['committed']['memory_layers'][0].update(digest='../foreign'))
        with self.assertRaisesRegex(RuntimeError,'digest/size'):
            m.memory_lower_inventory(rt,obs,Path('/owned'),templates)


if __name__=='__main__':unittest.main()
