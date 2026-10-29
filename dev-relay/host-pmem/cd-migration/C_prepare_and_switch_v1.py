"""C-only native adapter build and controlled module switch. Requires separate maintenance approval."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import sys
import types
import zlib

BASE64_HELPER = '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'
HELPER_SHA = 'b05df5d3cd17db1b0d7d51fc7b3f53d5341d256fc74c0788dadc242f89e4360e'
BASE64_ADAPTER = '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'
ADAPTER_SHA = '867ba18e0be748dbf9c3d081c45f8536be6630adbe98390dc9aaae78aff91e7a'
ROOT = Path('/var/lib/agentenv-c-rootfs-maintenance-v1')
APPROVAL = 'C_NATIVE_ADAPTER_BUILD_OBMM_SWITCH_EXPLICIT_RESTORE'


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def unpack(value, digest):
    raw = zlib.decompress(base64.b64decode(value, validate=True))
    need(hashlib.sha256(raw).hexdigest() == digest, 'Embedded reviewed source differs')
    return raw


def private_write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def process(pid):
    import pwd
    path = Path('/proc') / str(pid)
    status = (path / 'status').read_text()
    uids = next(line.split()[1:] for line in status.splitlines() if line.startswith('Uid:'))
    need(uids == [str(pwd.getpwnam('ubse').pw_uid)] * 4 and '/system.slice/ubse.service' in (path / 'cgroup').read_text(),
         'Unexpected UBSE process identity')
    return {'pid': pid, 'ticks': (path / 'stat').read_text().rsplit(')', 1)[1].split()[19]}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('mode', choices=('plan', 'activate', 'status', 'restore'), nargs='?', default='plan')
    p.add_argument('--approval')
    args = p.parse_args()
    if args.mode == 'plan':
        print(json.dumps({'scope': 'C only; compile adapter without executing it, switch OBMM, restart only UBSE',
            'approval': APPROVAL, 'logicalUbAllocationBytes': 0, 'SDK_called': False, 'Guest_created': False,
            'stage': str(ROOT), 'defaultChanges': False}, indent=2)); return
    need(os.getuid() == os.geteuid() == 0 and args.approval == APPROVAL, 'Separate explicit C maintenance approval required')
    preflight = Path('/var/lib/agentenv-c-rootfs-preflight-v1/receipt.json')
    need(preflight.resolve() == preflight and preflight.stat().st_uid == 0
         and not stat.S_IMODE(preflight.stat().st_mode) & 0o022, 'Preflight receipt untrusted')
    report = json.loads(preflight.read_bytes())
    need(report['status'] == 'C_ROOT_COMPATIBILITY_INSPECTED_NO_SDK_OR_KERNEL_ACTION'
         and report['machineId'] == Path('/etc/machine-id').read_text().strip()
         and report['bootId'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip()
         and report['kernel'] == platform.release(), 'C preflight machine/boot/kernel differs')
    helper = types.ModuleType('reviewed_maintenance_v2')
    exec(compile(unpack(BASE64_HELPER, HELPER_SHA), '<reviewed-maintenance-v2>', 'exec'), helper.__dict__)
    helper.process = process
    helper.NODE = platform.node(); helper.BOOT = report['bootId']; helper.STAGE = ROOT / 'module'
    helper.NEW_FILE = Path(report['candidate']['path']); helper.APPROVAL = APPROVAL
    context_path = ROOT / 'initial-context.json'
    if args.mode == 'activate':
        need(not ROOT.exists() and ROOT.resolve() == ROOT, 'Prior maintenance exists; use status/restore, do not retry')
        need(helper.read('/sys/module/obmm/srcversion') == helper.OLD_SRC, 'Original module identity differs')
        sections = report['ubse']['stdout'].strip().split('\n\n')
        service_rows = [dict(line.split('=',1) for line in section.splitlines() if '=' in line) for section in sections]
        old_pid = int(next(row for row in service_rows if row.get('Id') == 'ubse.service')['MainPID'])
        current = helper.service()
        need(current['ActiveState'] == 'active' and int(current['MainPID']) == old_pid, 'UBSE changed since approved preflight')
        context = {'params': {q.name: helper.read(q) for q in Path('/sys/module/obmm/parameters').iterdir()},
                   'taint': helper.read('/proc/sys/kernel/tainted'), 'process': process(old_pid),
                   'machineId': report['machineId'], 'bootId': report['bootId']}
        helper.PARAMS = context['params']; helper.EXPECTED_TAINT = context['taint']; helper.EXPECTED_PROCESS = context['process']
        helper.Local({}).check_old()
        ROOT.mkdir(mode=0o700); os.chmod(ROOT, 0o700)
        private_write(ROOT / 'entry.py', Path(__file__).read_bytes())
        private_write(context_path, (json.dumps(context, indent=2) + '\n').encode())
        build = ROOT / 'build'; build.mkdir(mode=0o700)
        cpp = build / 'sdk_adapter.cpp'; private_write(cpp, unpack(BASE64_ADAPTER, ADAPTER_SHA))
        # Compile against actual installed headers, including ubs_mem_def.h. Never dlopen or execute the output.
        need(hashlib.sha256(Path('/usr/lib64/libubsm_sdk.so').read_bytes()).hexdigest() == report['sdk']['sha256']
             and hashlib.sha256(Path('/usr/include/ubs_mem.h').read_bytes()).hexdigest() == report['header']['sha256'],
             'SDK/header changed since preflight')
        command = [helper.tool('g++'), '-std=c++17', '-O2', '-fPIC', '-shared', '-Wl,-z,defs',
                   str(cpp), '-o', str(build / 'libaenv-ub-sdk13.so'), '-lubsm_sdk', '-pthread']
        output = helper.command(command, timeout=120)
        helper.write_json(ROOT / 'native-build.json', {'SDK_called': False, 'adapterSourceSha256': ADAPTER_SHA,
            'adapterSha256': helper.sha((build / 'libaenv-ub-sdk13.so').read_bytes()),
            'headerDefSha256': helper.sha(Path('/usr/include/ubs_mem_def.h').read_bytes()),
            'sdkSha256': report['sdk']['sha256'], 'compilerOutput': output[-2000:]})
    else:
        need(ROOT.resolve() == ROOT and ROOT.stat().st_uid == 0 and not ROOT.stat().st_mode & 0o077,
             'Untrusted maintenance directory')
        context = json.loads(context_path.read_bytes())
        need(context['machineId'] == report['machineId'] and context['bootId'] == report['bootId'], 'Recovery context differs')
        helper.PARAMS = context['params']; helper.EXPECTED_TAINT = context['taint']; helper.EXPECTED_PROCESS = context['process']
        if not helper.STAGE.exists():
            need(args.mode == 'restore', 'Module stage not created; use restore for original-state validation')
            helper.Local({}).check_old()
            print('C_ORIGINAL_MODULE_AND_UBSE_UNCHANGED_NATIVE_BUILD_OUTPUTS_PRESERVED'); return
    sys.argv = [str(ROOT / 'entry.py'), args.mode, '--approval', APPROVAL]
    code = helper.main()
    if code == 0 and args.mode == 'activate':
        print('C_CANDIDATE_MODULE_ACTIVE_NATIVE_ADAPTER_BUILT_NO_UB_OR_GUEST')
    elif code == 0 and args.mode == 'restore':
        print('C_ORIGINAL_MODULE_UBSE_RESTORED_BUILD_OUTPUTS_PRESERVED')
    raise SystemExit(code)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(json.dumps({'status': 'C_MAINTENANCE_STOPPED_PRESERVE_STATE', 'reason': str(e),
            'explicitRecovery': '/usr/bin/python3 -I -B ' + str(ROOT / 'entry.py') + ' restore --approval ' + APPROVAL}))
        raise SystemExit(1)
