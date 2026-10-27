import ctypes, importlib.util, json, os, subprocess, sys, types, unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
if sys.platform=='win32':sys.modules['fcntl']=types.ModuleType('fcntl')
spec=importlib.util.spec_from_file_location('dead_chars',HERE/'delete_dead_chars_and_stage_body.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class GuardTests(unittest.TestCase):
    def observation(self,remaining):
        return {'unit':{'MainPID':'0','ActiveState':'inactive','Job':''},'processes':[],
         'devices':{**{f'ublkb{i}':None for i in (12,13)},
                    **{f'ublkc{i}':{'major':242,'minor':i,'expectedIdentity':True} if i in remaining else None for i in (12,13)}},
         'sysfsRemaining':[f'/sys/class/ublk-char/ublkc{i}' for i in remaining]}
    def test_actual_return_allows_only_chars(self):self.assertTrue(m.known_remainder(self.observation({12,13}),{12,13}))
    def test_partial_and_final(self):
        for remaining in ({13},set()):self.assertTrue(m.known_remainder(self.observation(remaining),remaining))
    def test_live_unit_rejected(self):
        value=self.observation({12,13});value['unit']['MainPID']='123';self.assertFalse(m.known_remainder(value,{12,13}))
    def test_unknown_process_rejected(self):
        value=self.observation({12,13});value['processes']=[{'pid':123}];self.assertFalse(m.known_remainder(value,{12,13}))
    def test_block_reappeared_rejected(self):
        value=self.observation({12,13});value['devices']['ublkb12']={'major':259,'minor':16};self.assertFalse(m.known_remainder(value,{12,13}))
    def test_reused_or_missing_char_rejected(self):
        for row in (None,{'major':243,'minor':12,'expectedIdentity':False}):
            value=self.observation({12,13});value['devices']['ublkc12']=row;self.assertFalse(m.known_remainder(value,{12,13}))
    def test_extra_sysfs_rejected(self):
        value=self.observation({12,13});value['sysfsRemaining'].append('/sys/class/ublk-char/ublkc99');self.assertFalse(m.known_remainder(value,{12,13}))


def rust_checks():
    source=(HERE/'dead-ublk-helper/src/main.rs').read_text();start=source.index('fn accepted(');end=source.index('\n}\n',start)+3
    predicate=source[start:end]
    harness='''#![allow(non_camel_case_types)]
mod ublk_sys {
 pub const UBLK_S_DEV_DEAD:u32=0;
 #[derive(Clone)] pub struct ublksrv_ctrl_dev_info {pub dev_id:u32,pub state:u16,pub ublksrv_pid:i32,pub owner_uid:u32,pub owner_gid:u32}
}
'''+predicate+'''
#[test] fn accepts_only_reviewed_dead_owner() {
 let good=ublk_sys::ublksrv_ctrl_dev_info{dev_id:12,state:0,ublksrv_pid:-1,owner_uid:1204,owner_gid:1205};
 assert!(accepted(&good,12));assert!(!accepted(&good,13));
 let mut x=good.clone();x.dev_id=13;assert!(accepted(&x,13));
 x.dev_id=14;assert!(!accepted(&x,14));
 for state in [1,2,65535] {let mut x=good.clone();x.state=state;assert!(!accepted(&x,12));}
 for pid in [0,3966531,123] {let mut x=good.clone();x.ublksrv_pid=pid;assert!(!accepted(&x,12));}
 let mut x=good.clone();x.owner_uid=0;assert!(!accepted(&x,12));
 let mut x=good.clone();x.owner_gid=0;assert!(!accepted(&x,12));
}
'''
    directory=HERE/'dead-char-local-tests';directory.mkdir(exist_ok=True);tmp=directory/'tmp';tmp.mkdir(exist_ok=True)
    path=directory/'guard.rs';path.write_text(harness)
    root=HERE.parents[1];old=root/'outputs/ub-implementation-20261017';rust=old/'local-rust/sysroot'
    def short(p):
        buf=ctypes.create_unicode_buffer(32768);assert ctypes.windll.kernel32.GetShortPathNameW(str(p),buf,len(buf));return buf.value.replace('\\','/')
    env=dict(os.environ,TEMP=short(tmp),TMP=short(tmp))
    compiler=rust/'bin/rustc.exe';lib=rust/'lib/rustlib/x86_64-pc-windows-gnu'
    env['PATH']=short(lib/'bin/self-contained')+';'+short(rust/'bin')+';'+env['PATH']
    exe=directory/'guard.exe'
    subprocess.run([str(compiler),'--edition=2021','--test',short(path),'--sysroot',short(rust),'-C','link-self-contained=yes',
        '-C','linker='+short(lib/'bin/self-contained/x86_64-w64-mingw32-gcc.exe'),'-o',short(directory)+'/guard.exe'],env=env,check=True)
    subprocess.run([str(exe)],env=env,check=True)
    return {'exactRustPredicateTested':True,'nativeSyscallsExecuted':False}


if __name__=='__main__':
    result=unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(GuardTests))
    if not result.wasSuccessful():raise SystemExit(1)
    evidence=rust_checks();evidence.update(pythonRecoveryTests=result.testsRun,targetExecuted=False)
    (HERE/'dead-char-local-tests.json').write_text(json.dumps(evidence,indent=2)+'\n')
