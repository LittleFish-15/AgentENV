"""Fix pre-start ublk authorization and derive retry/test worker without app changes."""
import ast
from pathlib import Path
H=Path(__file__).resolve().parent
s=(H/'device_broker011.py').read_text(encoding='utf-8').replace('broker-config011.json','broker-config017.json').replace('jwk-ublk-query\'','jwk-ublk-query017\'').replace('broker-ready011.json','broker-ready017.json')
needle="def grant(path,excluded):"
finder='''def prestart_daemon():
    candidates=[]
    for path in pathlib.Path('/proc').iterdir():
        if not path.name.isdigit():continue
        try:
            if path.stat().st_uid!=UID:continue
            if (path/'comm').read_text().strip()!='uvm-ublk-daemon':continue
            candidates.append(int(path.name))
        except OSError:continue
    assert len(candidates)==1,'Ambiguous or absent jwk ublk daemon'
    pid=candidates[0];return pid,process(pid)
'''
s=s.replace(needle,finder+needle)
old="""        info=json.loads(query.stdout);pid=int(info['pid']);assert pid>0 and info['id']==int(match[2])
        start=process(pid);assert signature(path.lstat())==signature(held)
        assert process(pid)==start"""
new="""        info=json.loads(query.stdout);pid=int(info['pid']);assert info['id']==int(match[2])
        assert info['ownerUid']==UID and info['ownerGid']==CONFIG['gid'],'Kernel owner differs'
        if 0<pid<2147483647:start=process(pid);phase='started'
        else:pid,start=prestart_daemon();phase='prestart-owner-verified'
        assert signature(path.lstat())==signature(held)
        assert process(pid)==start"""
assert old in s;s=s.replace(old,new)
s=s.replace("{'granted':path.name,'uid':UID,'daemonPid':pid}","{'granted':path.name,'uid':UID,'daemonPid':pid,'phase':phase,'kernelOwnerUid':info['ownerUid']}")
s=s.replace("        if query.returncode:return False","        if query.returncode:raise RuntimeError('Read-only kernel owner query failed: '+query.stderr[-1500:])")
s=s.replace("str(ROOT/'jwk-ublk-query017')","CONFIG['query']")
s=s.replace("    pending={}\n", "    pending={p.name:(time.monotonic(),time.monotonic()+3) for p in pathlib.Path('/dev').glob('ublk[cb]*') if re.fullmatch(r'ublk[cb]\\d+',p.name)}\n    reported=set()\n")
s=s.replace("            except (AssertionError,OSError,ValueError,subprocess.TimeoutExpired):\n                pass", "            except (AssertionError,OSError,ValueError,RuntimeError,subprocess.TimeoutExpired) as error:\n                detail=(name,type(error).__name__,str(error)[-1500:])\n                if detail not in reported:\n                    print(json.dumps({'pendingDevice':name,'errorType':detail[1],'detail':detail[2]}),flush=True);reported.add(detail)")
worker=(H/'wikidata015_worker.py').read_text(encoding='utf-8').replace("BASE/'wikidata015'","BASE/'wikidata017'").replace("NAME='swb-wikidata-wikidata-toolkit-717'","NAME='swb-wikidata-wikidata-toolkit-717-retry017'").replace('wikidata015.lock','wikidata017.lock').replace("BASE/'results/wikidata015'","BASE/'results/wikidata017'")
worker=worker.replace("'/manifests/'+TAG,accept)","'/manifests/sha256:a28574d78c51af2b341f769b484aed023406015cb2a249e985a0bbdcd022775b',accept)")
worker=worker.replace("return REG+'/'+REPO+'@'+digest,", "assert digest=='sha256:a28574d78c51af2b341f769b484aed023406015cb2a249e985a0bbdcd022775b'\n    return REG+'/'+REPO+'@'+digest,")
tests=(H/'test_runtime008.py').read_text(encoding='utf-8').replace('device_broker008.py','device_broker017.py')
tests=tests.replace("'UID':1002,'CGROUP'", "'UID':1002,'CONFIG':{'gid':1002,'query':'/var/lib/own/query'},'CGROUP'")
tests=tests.replace('def grant(self,race=False,excluded=False):','def grant(self,race=False,excluded=False,prestart=False,foreign=False):')
tests=tests.replace("self.env['process']=lambda pid:'456'", "self.env['process']=lambda pid:'456'\n        self.env['prestart_daemon']=lambda:(123,'456')")
tests=tests.replace("{'id':10,'pid':123}","{'id':10,'pid':0 if prestart else 123,'ownerUid':0 if foreign else 1002,'ownerGid':1002}")
tests=tests.replace("if __name__=='__main__':unittest.main()", """    def test_prestart_kernel_owner_can_be_granted(self):
        self.assertTrue(self.grant(prestart=True));self.assertEqual(len(self.calls),1)
    def test_foreign_kernel_owner_is_never_granted(self):
        with self.assertRaises(AssertionError):self.grant(foreign=True)
        self.assertEqual(self.calls,[])
if __name__=='__main__':unittest.main()""")
for name,body in [('device_broker017.py',s),('wikidata017_worker.py',worker),('test_broker017.py',tests)]:
    ast.parse(body,feature_version=(3,11));(H/name).write_bytes(body.encode())
print('Broker017 verifies kernel owner before PID is assigned; worker uses same pinned native image and new retry template')
