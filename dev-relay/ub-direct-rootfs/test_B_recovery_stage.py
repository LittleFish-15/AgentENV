import importlib.util,json,re,stat,sys,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).parent
if sys.platform=='win32':sys.modules['fcntl']=types.ModuleType('fcntl')
spec=importlib.util.spec_from_file_location('B_recovery',HERE/'recover_B_and_stage_body.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class RecoveryContracts(unittest.TestCase):
    def filesystem(self,remaining):
        captured={i:{'major':242,'inode':100+i,'ctimeSeconds':12345,'ctimeNanoseconds':456} for i in (0,1)}
        files={}
        for i in remaining:
            files[f'/dev/ublkc{i}']=types.SimpleNamespace(st_mode=stat.S_IFCHR,st_rdev=242*256+i,
                st_ino=100+i,st_ctime_ns=12345*10**9+456)
            files[f'/sys/class/ublk-char/ublkc{i}']=None
        class Item:
            def __init__(self,name):self.name=str(name)
            def exists(self):return self.name in files
            def is_symlink(self):return False
            def lstat(self):return files[self.name]
            def __str__(self):return self.name
        return captured,files,Item
    def check(self,remaining,change=None):
        captured,files,item=self.filesystem(remaining)
        if change:change(files)
        with patch.object(m,'Path',item),patch.object(m.os,'major',lambda x:x//256,create=True),patch.object(m.os,'minor',lambda x:x%256,create=True):
            return m.residual_chars(captured)
    def test_clean_exit_skips_kernel_helper(self):self.assertEqual(self.check(set()),[])
    def test_only_reviewed_remaining_chars_selected(self):
        self.assertEqual(self.check({0,1}),[0,1]);self.assertEqual(self.check({1}),[1])
    def test_live_block_prevents_deletion(self):
        with self.assertRaisesRegex(RuntimeError,'block device still present'):self.check({0,1},lambda f:f.update({'/dev/ublkb0':None}))
    def test_reused_inode_prevents_deletion(self):
        def change(files):files['/dev/ublkc0'].st_ino+=1
        with self.assertRaisesRegex(RuntimeError,'incarnation changed'):self.check({0,1},change)
    def test_sysfs_without_node_stops(self):
        with self.assertRaisesRegex(RuntimeError,'sysfs remains'):self.check({0},lambda f:f.pop('/dev/ublkc0'))
    def test_health_report_contract(self):
        report={'status':'DIRECT_GUEST_RUNTIME_HEALTHY_NO_GUEST_YET','CLI_list_count':0}
        text='BEGIN_DIRECT_GUEST_RUNTIME_REPORT\n'+json.dumps(report)+'\nEND_DIRECT_GUEST_RUNTIME_REPORT\n'
        self.assertEqual(m.parse_health(text),report)
        with self.assertRaises(RuntimeError):m.parse_health(text.replace('"CLI_list_count": 0','"CLI_list_count": 1'))


if __name__=='__main__':
    result=unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(RecoveryContracts))
    if not result.wasSuccessful():raise SystemExit(1)
    # Reuse the exact production-predicate harness with B-specific source/IDs.
    source=(HERE/'test_dead_char_recovery.py').read_text()
    source=source.replace("HERE/'dead-ublk-helper/src/main.rs'","HERE/'dead-ublk-helper-b/src/main.rs'").replace("HERE/'dead-char-local-tests'","HERE/'dead-char-B-local-tests'")
    start=source.index('def rust_checks():');end=source.index("\n\nif __name__",start)
    function=source[start:end]
    for old,new in [('12','0'),('13','1'),('14','2')]:function=re.sub(r'\b'+old+r'\b',new,function)
    import ctypes,os,subprocess
    scope={'HERE':HERE.resolve(),'Path':Path,'ctypes':ctypes,'os':os,'subprocess':subprocess}
    exec(compile(function,'<same-Rust-predicate-harness-for-B>','exec'),scope)
    checked=scope['rust_checks']();checked.update(pythonRecoveryTests=result.testsRun,targetExecuted=False)
    (HERE/'B-recovery-local-tests.json').write_text(json.dumps(checked,indent=2)+'\n')
