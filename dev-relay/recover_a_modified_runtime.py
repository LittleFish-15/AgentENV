"""Complete A modified restart-state repair after the attestation collision.

Reuses the reviewed socket recovery and exact unit reactivation. Only the
runtime-attestation write changes; immutable installation put/dump stay strict.
"""
import argparse
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import tempfile

ROOT=Path('/home/jwk/agent')
PREVIOUS_RECOVERY=ROOT/'relay/cow-modified-proxy-recovery-node-a.json'
RECOVERY=ROOT/'relay/cow-modified-runtime-recovery-node-a.json'
RECOVERY_HELPER_SHA='f87fe5b57d653bff80443cbfc0ee05ac8b63119f789a822771724dec9f438b75'
ATTESTATION_SOURCE='def publish_runtime_attestation(value):\n    """Refresh only the current unit\'s process record; immutable install files stay immutable."""\n    require(os.getuid() == os.geteuid() == 1204, \'Expected runtime owner\')\n    require(int(properties(UNIT).get(\'MainPID\', 0)) == os.getpid(), \'Attestation writer is not unit main process\')\n    require(value.get(\'pid\') == os.getpid() and value.get(\'revision\') == REVISION\n            and value.get(\'intended_executable\') == str(D / \'bin/server\')\n            and value.get(\'uid\') == [1204] * 4, \'Unexpected new attestation identity\')\n    path = safe(RUNTIME / \'runtime-attestation.json\')\n    data = (json.dumps(value, indent=2, sort_keys=True) + \'\\n\').encode()\n    if not path.exists():\n        put(path, data)\n        return\n    before, metadata = stable_file(path, 65536)\n    old = json.loads(before)\n    require(old.get(\'revision\') == REVISION and old.get(\'intended_executable\') == str(D / \'bin/server\')\n            and old.get(\'uid\') == [1204] * 4 and type(old.get(\'pid\')) is int and old[\'pid\'] > 1\n            and isinstance(old.get(\'start_ticks\'), str) and old[\'start_ticks\'].isdigit(),\n            \'Unknown existing runtime attestation preserved\')\n    if old[\'pid\'] == value[\'pid\'] and old[\'start_ticks\'] == value[\'start_ticks\']:\n        require(before == data, \'Current-process attestation differs; preserved\')\n        return\n    try:\n        ticks = Path(\'/proc/\' + str(old[\'pid\']) + \'/stat\').read_text().rsplit(\')\', 1)[1].split()[19]\n    except FileNotFoundError:\n        ticks = None\n    require(ticks != old[\'start_ticks\'], \'Previous attested process is still alive; preserved\')\n    backup = safe(RUNTIME / (\'runtime-attestation-history-\' + secrets.token_hex(12) + \'.json\'))\n    put(backup, before)\n    temporary = safe(RUNTIME / (\'runtime-attestation-new-\' + secrets.token_hex(12) + \'.json\'))\n    try:\n        put(temporary, data)\n        current, current_meta = stable_file(path, 65536)\n        require(current == before and (metadata.st_dev, metadata.st_ino, metadata.st_mtime_ns)\n                == (current_meta.st_dev, current_meta.st_ino, current_meta.st_mtime_ns),\n                \'Runtime attestation changed concurrently; preserved\')\n        require(int(properties(UNIT).get(\'MainPID\', 0)) == os.getpid(), \'Unit changed before attestation publication\')\n        os.replace(temporary, path)\n    finally:\n        if temporary.exists():\n            temporary.unlink()\n'
H=None

def patch_launcher(raw):
    text=raw.decode()
    old="dump(RUNTIME / 'runtime-attestation.json', attestation)"
    H.need(text.count(old)==1 and text.count('def inside():')==1
           and text.count('def prepare_inside_socket(')==1 and text.count('prepare_inside_socket(unix, lock)')==1
           and 'def publish_runtime_attestation(' not in text,'Unknown/already repaired launcher; preserve')
    new=text.replace('def inside():',ATTESTATION_SOURCE+'\n\ndef inside():',1)
    new=new.replace(old,'publish_runtime_attestation(attestation)',1)
    ast.parse(new);return new.encode()

def main():
    global H
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--apply-reviewed',action='store_true');args=parser.parse_args()
    if not(socket.gethostname()=='server1' and os.getuid()==os.geteuid()==1204 and os.getgid()==os.getegid()==1205):raise RuntimeError('A ordinary jwk only')
    caps=re.findall(r'^Cap(?:Inh|Prm|Eff|Amb):\s*(\w+)$',Path('/proc/self/status').read_text(),re.M)
    if len(caps)!=4 or any(int(v,16) for v in caps):raise RuntimeError('Capability-free launcher required')
    helper=ROOT/'recover_modified_proxy_ceb26a9.py';raw=helper.read_bytes()
    if helper.resolve(strict=True)!=helper or hashlib.sha256(raw).hexdigest()!=RECOVERY_HELPER_SHA:raise RuntimeError('Pinned prior recovery helper differs')
    spec=importlib.util.spec_from_file_location('socket_recovery',helper)
    F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
    S=F.load(ROOT/'cow_modified_d2285fe.py',F.COMPARE_SHA,'comparison')
    C=F.load(ROOT/'cow_controlled_engine.py',S.ENGINE_SHA,'engine')
    P=C.load(ROOT/'cow_marker_prepare_e5b9050.py',C.PREPARE_SHA,'marker')[0]
    H=P.load_parent();C.H=H;S.H=H
    R=C.load(ROOT/'cow_ram_readonly.py',C.COLLECTOR_SHA,'reader')[0];S.R=R
    F.H=H;F.S=S;F.R=R;F.RECOVERY=RECOVERY;F.patched_launcher=patch_launcher
    os.umask(0o077);import fcntl
    with open(H.safe(ROOT/'relay/cow-modified-node-a.lock'),'a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        work=Path(tempfile.mkdtemp(prefix='node-a-runtime-recovery-',dir=H.safe(ROOT/'relay/reports')))
        try:
            previous=json.loads(H.read(PREVIOUS_RECOVERY))
            prior=json.loads(H.read(F.PREP))
            H.need(previous.get('status')=='A_MODIFIED_PROXY_REPAIRED_UNIT_NOT_STARTED'
                   and prior.get('proxy_recovery_report')==previous.get('report_directory'),
                   'Prior socket repair receipt mismatch; preserve')
            report=F.recover(work,args.apply_reviewed)
            report['revision']='a-modified-runtime-recovery-v2'
            report['prior_recovery_report']=previous['report_directory']
            report['runtime_record_policy']='Exact current-unit attestation only; archive old known dead identity, atomic replace; immutable put/dump unchanged'
            if args.apply_reviewed:
                report['status']='A_MODIFIED_RUNTIME_REPAIRED_UNIT_NOT_STARTED';H.save(RECOVERY,report)
        except (Exception,KeyboardInterrupt) as e:
            report={'status':'STOPPED_MODIFIED_RUNTIME_RECOVERY','report_directory':str(work),'error_type':type(e).__name__,
                    'reason':str(e) if isinstance(e,RuntimeError) else 'Preserve backups and receipts; no retry'}
        H.save(work/'return.json',report)
        print('BEGIN_RETURN_REPORT');print(json.dumps(report,indent=2));print('END_RETURN_REPORT')
        return 1 if report['status'].startswith('STOPPED') else 0
if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as e:
        print('BEGIN_RETURN_REPORT');print(json.dumps({'status':'STOPPED_RUNTIME_RECOVERY_ENTRY','error_type':type(e).__name__,
              'reason':str(e) if isinstance(e,RuntimeError) else 'Entry failed'}));print('END_RETURN_REPORT');raise SystemExit(1)
