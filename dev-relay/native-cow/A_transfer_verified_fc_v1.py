"""User-run A to B transfer of the two already validated experiment artifacts.
No SSH is performed by the assistant. --run uses the user's normal SSH identity.
"""
import argparse,hashlib,io,json,os,shlex,subprocess,tarfile
from pathlib import Path
ROOT=Path('/home/jwk/agent')
INPUTS={
 'firecracker':('builds/fc-native-pmem-v1/stage/artifacts/firecracker','ce17c76b9a62656f455138624781ca1e583eeb059658101840a51f257cb6f01d',8505784),
 'policy.bpf':('r/pm-a-v1/native-session/futex-v5/policy-vmm-futex265.bpf','afa4de05b17b89dec5c9a8f03b4852f836b45b28c76f6bdde812bd84ede2af00',2810),
}
RECEIVER=r'''
import hashlib,io,json,os,stat,sys,tarfile
from pathlib import Path
assert os.getuid()==os.geteuid()==1204 and os.uname().nodename=='agent1','Use B jwk account'
base=Path('/home/jwk/agent/r/pm-b-v1')
assert base.resolve(strict=True)==base and base.stat().st_uid==1204
target=base/'fc-receive-v1'
pins={'firecracker':('ce17c76b9a62656f455138624781ca1e583eeb059658101840a51f257cb6f01d',8505784),
      'policy.bpf':('afa4de05b17b89dec5c9a8f03b4852f836b45b28c76f6bdde812bd84ede2af00',2810)}
data=sys.stdin.buffer.read(12*1024**2+1);assert len(data)<=12*1024**2
files={}
with tarfile.open(fileobj=io.BytesIO(data),mode='r:') as archive:
 members=archive.getmembers();assert len(members)==2 and {x.name for x in members}==set(pins)
 for entry in members:
  assert entry.isfile() and entry.size==pins[entry.name][1]
  content=archive.extractfile(entry).read(entry.size+1)
  assert len(content)==entry.size and hashlib.sha256(content).hexdigest()==pins[entry.name][0]
  files[entry.name]=content
assert not target.is_symlink()
if target.exists():
 assert target.resolve(strict=True)==target and target.stat().st_uid==1204 and set(x.name for x in target.iterdir())==set(pins),'Existing incomplete/foreign directory preserved'
 for name,content in files.items():
  path=target/name;assert path.resolve(strict=True)==path and path.is_file() and path.stat().st_uid==1204 and path.read_bytes()==content,'Existing different file preserved'
else:
 os.umask(0o077);target.mkdir(mode=0o700)
 for name,content in files.items():
  path=target/name
  with path.open('xb') as stream:stream.write(content);stream.flush();os.fsync(stream.fileno())
  path.chmod(0o500 if name=='firecracker' else 0o400)
print(json.dumps({'status':'B_VERIFIED_FC_AND_POLICY_RECEIVED_NOT_DEPLOYED','directory':str(target),'SDK_called':False,'Guest_created':False,'services_changed':False}))
'''

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run',action='store_true');args=parser.parse_args()
    if not args.run:
        print(json.dumps({'status':'PLAN_ONLY','destination':'jwk@agent1','files':list(INPUTS),'services_changed':False}));return 0
    assert os.getuid()==os.geteuid()==1204 and os.uname().nodename=='server1','Use A ordinary jwk'
    archive=io.BytesIO()
    with tarfile.open(fileobj=archive,mode='w') as tar:
        for name,(relative,pin,count) in INPUTS.items():
            path=ROOT/relative;assert path.resolve(strict=True)==path
            with path.open('rb') as stream:
                before=os.fstat(stream.fileno());data=stream.read(count+1);after=os.fstat(stream.fileno())
            assert (before.st_ino,before.st_size,before.st_mtime_ns)==(after.st_ino,after.st_size,after.st_mtime_ns)
            assert len(data)==count and hashlib.sha256(data).hexdigest()==pin,'Validated A artifact changed'
            member=tarfile.TarInfo(name);member.size=len(data);tar.addfile(member,io.BytesIO(data))
    print('PHASE=user_SSH_transfer_validated_FC_and_filter_to_B_no_service_change',flush=True)
    command=['ssh','-T','-o','ConnectTimeout=15','jwk@agent1','python3 -I -B -c '+shlex.quote(RECEIVER)]
    return subprocess.run(command,input=archive.getvalue(),timeout=180).returncode

if __name__=='__main__':raise SystemExit(main())
