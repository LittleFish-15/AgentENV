"""B exports its original ready receipt into an offline A write command.

Human copy only. B makes no API/SDK call and does not mutate experiment state.
The printed A command executes only the previously pinned write-a phase.
"""
import base64, hashlib, json, os, platform, stat, sys, zlib
from pathlib import Path

ROOT = Path('/home/jwk/agent')
WORK = ROOT / 'deployments/agentenv-direct-ub-guest-v1/acceptance/direct-pair-v1'
CONTROLLER_SHA = '6c01a15e36a056b29a400e52f33f38981ff0abf3ca939185e6a4074dd9fda1fa'
RUN = 'ca0e30a36541483eaa26ff38ead95f8f'


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def read_record(path):
    need(path.resolve(strict=True) == path and path.is_relative_to(ROOT), 'Redirected record')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
             and before.st_size <= 65536, 'Record identity/size differs')
        raw = stream.read(65537)
        after = os.fstat(stream.fileno())
    stamp = lambda m: (m.st_dev, m.st_ino, m.st_size, m.st_mtime_ns, m.st_ctime_ns)
    need(stamp(before) == stamp(after) == stamp(path.lstat()) and len(raw) == before.st_size, 'Record changed')
    return raw, json.loads(raw)


def validate_b_records(ready, report, state):
    need(report['status'] == 'DIRECT_UB_ONE_REAL_GUEST_READY_RETAINED'
         and report['singleGuestReadAndBindingPassed'] is True
         and report['coreCommit'] == 'ff1efdd9a2598e19b84cc09b91c8bc1e10ab6254', 'B ready report incomplete')
    need(ready['version'] == 1 and ready['kind'] == 'ready' and ready['node'] == report['node'] == 'b'
         and ready['runId'] == report['pairRunId'] == state['runId'] == RUN, 'B pair identity differs')
    need(ready['ownerId'] == report['provider']['ownerId'] == '563b042793d747b085a286e221a97993'
         and ready['manifestSha256'] == report['provider']['manifestSha256']
         == 'sha256:92974af667c6e01c3394c76e9eb3a5e40aa508dd736ad189200a266384bb4ec0', 'B base identity differs')
    need(ready['templateId'] == '01a15c9e-54d0-7b92-a50b-0b6ec2e9136b'
         and ready['sandboxId'] == report['sandboxId'] == report['binding']['sandboxId']
         and ready['base'] == report['base'] and ready['written'] is None
         and ready['guestExitConfirmed'] is False, 'B ready content differs')
    need(state['phase'] == 'active' and state['sandboxIds'] == [ready['sandboxId']]
         and state['openRequests'] == [] and state['outcomeUncertain'] is False, 'B lifecycle unresolved')


def a_command(controller, peer):
    need(hashlib.sha256(controller).hexdigest() == CONTROLLER_SHA, 'Controller bytes differ')
    need(len(peer) <= 65536 and isinstance(json.loads(peer), dict), 'Peer receipt exceeds bound')
    code = '''import base64,hashlib,os,platform,stat,sys,zlib
from pathlib import Path
assert os.getuid()==os.geteuid()==0 and platform.node()=='server1'
raw=zlib.decompress(base64.b64decode(CONTROLLER,validate=True))
assert len(raw)==18980 and hashlib.sha256(raw).hexdigest()==PIN
peer=base64.b64decode(PEER,validate=True)
assert len(peer)<=65536 and hashlib.sha256(peer).hexdigest()==PEER_PIN
root=Path('/home/jwk/agent')
work=root/'deployments/agentenv-direct-ub-guest-v1/acceptance/direct-pair-v1'
assert work.resolve(strict=True)==work and work.stat().st_uid==0
def put(path,data):
    assert path.parent.resolve(strict=True)==path.parent and not path.is_symlink()
    if path.exists():
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        with os.fdopen(fd,'rb') as stream:
            m=os.fstat(stream.fileno())
            assert stat.S_ISREG(m.st_mode) and m.st_uid in (0,1204) and m.st_nlink==1 and m.st_mode&0o022==0
            assert stream.read(len(data)+1)==data
    else:
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(data);stream.flush();os.fsync(stream.fileno())
controller=root/'actual_guest_pair_continue_v2.py'
receipt=work/'relay-b-ready.json'
put(controller,raw);put(receipt,peer)
print('A_WRITE_CONTROLLER_AND_B_ORIGINAL_RECEIPT_VERIFIED',flush=True)
sys.argv=[str(controller),'write-a','--peer',str(receipt),'--run']
exec(compile(raw,str(controller),'exec'),{'__name__':'__main__','__file__':str(controller)})
'''
    header = 'CONTROLLER=' + repr(base64.b64encode(zlib.compress(controller, 9)).decode()) + '\n'
    header += 'PIN=' + repr(CONTROLLER_SHA) + '\n'
    header += 'PEER=' + repr(base64.b64encode(peer).decode()) + '\n'
    header += 'PEER_PIN=' + repr(hashlib.sha256(peer).hexdigest()) + '\n'
    return "python3 -I -B - <<'UB_A_WRITE_FROM_B_READY'\n" + header + code + 'UB_A_WRITE_FROM_B_READY\n'


def main():
    need(sys.platform == 'linux' and os.getuid() == os.geteuid() == 0
         and platform.node() == 'agent1', 'Export only on B/agent1 as root')
    import fcntl
    need(WORK.resolve(strict=True) == WORK and WORK.stat().st_uid == 0, 'Pair directory changed')
    fd = os.open(WORK / 'run.lock', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        meta = os.fstat(fd)
        need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and meta.st_nlink == 1, 'Pair lock changed')
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        need(not (WORK / 'pair-phases.json').exists(), 'B continuation already has state; do not restart relay')
        rows = {name: read_record(WORK / name) for name in ('ready-receipt.json', 'report.json', 'state.json')}
        validate_b_records(*(rows[name][1] for name in ('ready-receipt.json', 'report.json', 'state.json')))
        for name, row in rows.items():
            need(read_record(WORK / name)[0] == row[0], 'B records changed during export')
        controller = zlib.decompress(base64.b64decode(CONTROLLER_Z64, validate=True))
        command = a_command(controller, rows['ready-receipt.json'][0])
        print('B_ORIGINAL_READY_EXPORTED_NO_GUEST_ACTION')
        print('Copy ONLY the command between the following markers to A/server1 root. Run once; preserve any STOPPED result.')
        print('BEGIN_A_WRITE_COMMAND')
        print(command, end='')
        print('END_A_WRITE_COMMAND')
    finally:
        os.close(fd)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'status': 'STOPPED_B_READY_EXPORT_NO_GUEST_ACTION',
                          'errorType': type(error).__name__, 'reason': str(error), 'resourcesChanged': False}))
        raise SystemExit(1)
