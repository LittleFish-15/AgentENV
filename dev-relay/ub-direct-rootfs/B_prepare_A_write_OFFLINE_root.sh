python3 -I -B - <<'UB_EXPORT_B_READY_FOR_A_WRITE'
CONTROLLER_Z64='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'
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

UB_EXPORT_B_READY_FOR_A_WRITE
