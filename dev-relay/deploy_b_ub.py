"""Restore B's installed original launcher context and stage the isolated UB build.

B/jwk: prepare -> copy three A build artifacts -> install -> reviewed root start
of the two precise units -> health -> health --post-disconnect.
No rebuild/download, SDK calls, account/device changes or automatic root action.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys
import tempfile
import types

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('aenv_ub_b_deployment_core', HERE / 'deploy_a_ub.py')
core = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = core
spec.loader.exec_module(core)
core.NODE = 'node-b'
core.EXPECTED_HOST = 'agent1'
core.STATUS_PREFIX = 'B_UB'
core.REVISION = 'aenv-ub-isolated-b-v1'
core.RUNTIME = core.ROOT / 'r/ub-b-b019'
core.UNIT = 'jwk-aenv-ub-b019f27-node-b.service'
core.OLD_UNIT = 'jwk-aenv-ae9c626-node-b.service'
core.ARTIFACTS = core.ROOT / 'relay/ub-b019f27-artifacts'
core.LAUNCHER = core.D / 'libexec/deploy_b_ub.py'
ORIGINAL_BINARIES = {
    'server': '0c5478b8382289c05ab1730401eea6918420c35594604cc7131592e81ad5aeff',
    'aenv': 'ac2cf76020ce2ed0cf06f1105e06c34534a35ed8247fca0cb57e2d53269771e1',
    'uvm-ublk-daemon': '13bd2ac381cf877348a39c0b198e2061479ae237c0f54cbcbeae0ab14e700172',
}
NORMAL_BASELINE = core.baseline
NORMAL_HEALTH = core.health
ROOT_TEXT_SHA256 = '710fc5bebca5774ed41cba9f0e5068acfb50423311619443c0b88b74c46a22dd'


def original_receipt():
    receipt = core.load(core.BASE / 'installation.json')
    core.require(receipt.get('revision') == 'aenv-offline-install-start-v4'
                 and receipt.get('node') == 'node-b'
                 and receipt.get('commit') == 'ae9c62693839ce7effa2b45df31c0039ae4f9fbc',
                 'Expected original B installation missing/different; no reinstall attempted')
    launcher = Path(receipt.get('launcher', ''))
    core.require(re.fullmatch(r'/home/jwk/agent/relay/aenv-run-v4-[0-9a-f]+/deployment\.py', str(launcher)),
                 'Original launcher is outside its installed v4 run; preserved')
    core.stable_file(launcher, 256 * 1024)
    for name, digest in ORIGINAL_BINARIES.items():
        data, _ = core.stable_file(core.BASE / 'bin' / name)
        core.require(hashlib.sha256(data).hexdigest() == digest, 'Original B binary differs: ' + name)
    return receipt, launcher


def prepare():
    core.identity()
    core.no_caps()
    import fcntl
    lock = os.open(core.ROOT / 'relay/aenv-ub-b019f27-install.lock',
                   os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        report_dir = Path(tempfile.mkdtemp(prefix='node-b-restore-services-', dir=core.ROOT / 'relay/reports'))
        receipt, launcher = original_receipt()
        state = core.properties(core.OLD_UNIT)
        boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        refreshed = False
        if receipt.get('boot_id') != boot_id:
            core.require(state.get('ActiveState') != 'active' and int(state.get('MainPID', 0)) == 0,
                         'Original unit is active with an older receipt; preserve it for review')
            # Only the three node-local launcher context fields, exactly as the
            # original v4 reinstall refresh did. No config, binary or state edit.
            before, _ = core.stable_file(core.BASE / 'installation.json', 65536)
            updated = dict(receipt, boot_id=boot_id,
                           host_netns=os.stat('/proc/self/ns/net').st_ino,
                           host_mntns=os.stat('/proc/self/ns/mnt').st_ino)
            core.put(report_dir / 'original-installation-before.json', before)
            temporary = report_dir / 'original-installation-new.json'
            core.dump(temporary, updated)
            core.require(core.stable_file(core.BASE / 'installation.json', 65536)[0] == before,
                         'Original receipt changed concurrently; no replacement attempted')
            os.replace(temporary, core.BASE / 'installation.json')
            refreshed = True
        marker = {'revision': 'b-ub-artifacts-v1', 'commit': core.COMMIT, 'sha256': core.BINARIES}
        incoming = core.ARTIFACTS
        core.safe(incoming)
        if incoming.exists() and any(incoming.iterdir()):
            core.require(core.load(incoming / 'input-definition.json') == marker, 'Unknown artifact directory preserved')
        core.mkdir(incoming)
        core.dump(incoming / 'input-definition.json', marker)
        ready = True
        for name, digest in core.BINARIES.items():
            path = incoming / name
            if not path.exists():
                ready = False
            else:
                core.require(hashlib.sha256(core.stable_file(path)[0]).hexdigest() == digest,
                             'Existing incoming artifact differs; preserved: ' + name)
        result = {'status': 'B_SERVICE_INPUT_DIRECTORY_READY', 'node': 'node-b', 'hostname': 'agent1',
                  'uid': 1204, 'report_directory': str(report_dir),
                  'original_launcher': str(launcher), 'original_context_refreshed_after_reboot': refreshed,
                  'original_active_before_prepare': state.get('ActiveState') == 'active',
                  'artifacts_directory': str(incoming), 'three_artifacts_already_verified': ready,
                  'service_started': False, 'binaries_or_config_overwritten': False, 'SDK_called': False}
        core.dump(report_dir / 'return.json', result)
        print('BEGIN_RETURN_REPORT')
        print(json.dumps(result, indent=2))
        print('END_RETURN_REPORT')
        return 0
    finally:
        os.close(lock)


def original_for_install():
    receipt, _ = original_receipt()
    core.require(receipt.get('boot_id') == Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                 'Run B prepare first to refresh its original launcher context')
    fields = core.properties(core.OLD_UNIT)
    if fields.get('ActiveState') == 'active':
        return NORMAL_BASELINE()
    core.require(int(fields.get('MainPID', 0)) == 0, 'Original process state unresolved; no install mutation')
    return None


def stage_b_launcher():
    library = core.D / 'libexec/deploy_a_ub.py'
    core.put(library, (HERE / 'deploy_a_ub.py').read_bytes())
    core.put(core.LAUNCHER, Path(__file__).read_bytes())
    return {library.name: hashlib.sha256(library.read_bytes()).hexdigest()}


def redact(text):
    text = re.sub(r'e2b_[A-Za-z0-9._~-]+', '[REDACTED]', str(text))
    # Do not include lines containing other authentication material in tails.
    return '\n'.join('[REDACTED authentication line]' if re.search(
        r'authorization|api[_ -]?key|password|secret|bearer\s|token\s*[:=]', line, re.I)
        else line for line in text.splitlines())


def read_tail(path):
    core.safe(path, True)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        meta = os.fstat(stream.fileno())
        core.require(stat.S_ISREG(meta.st_mode), 'Not a regular diagnostic file')
        stream.seek(max(0, meta.st_size - 6000))
        data = stream.read(6000)
    return {'mtime_ns': meta.st_mtime_ns, 'size': meta.st_size,
            'tail': redact(data.decode(errors='replace'))}


def service_diagnostics(base, runtime, unit, port):
    """Read both deployments even when the first health check fails. Never repair."""
    result = {'unit': unit, 'diagnostic_only': True, 'logs': {}, 'runtime_files': {}}
    commands = {
        'systemd': ['systemctl', 'show', unit, '--no-pager',
                    '--property=LoadState,ActiveState,SubState,MainPID,Result,ExecMainCode,ExecMainStatus,User,Group,PrivateNetwork,PrivateMounts,ActiveEnterTimestamp,InactiveEnterTimestamp'],
        'current_boot_journal': ['journalctl', '--no-pager', '-b', '-u', unit,
                                 '-n', '40', '-o', 'short-iso'],
    }
    for key, command in commands.items():
        try:
            rc, output = core.run(command, timeout=10)
            result[key] = {'rc': rc, 'output': redact(output[-12000:])}
        except Exception as error:
            result[key] = {'error': redact(error)}
    try:
        core.http_health(port)
        result['existing_http_endpoint'] = 204
    except Exception as error:
        result['existing_http_endpoint'] = {'error': redact(error)}
    for name in ('launcher.log', 'server.log', 'ublk-daemon.log', 'proxy-inside.log', 'proxy-host.log'):
        try:
            result['logs'][name] = read_tail(base / 'logs' / name)
        except Exception as error:
            result['logs'][name] = {'error': redact(error)}
    try:
        receipt = core.load(base / 'installation.json')
        result['installation_context'] = {k: receipt.get(k) for k in
            ('revision', 'node', 'boot_id', 'host_netns', 'host_mntns', 'launcher')}
        result['receipt_matches_current_boot'] = receipt.get('boot_id') == Path(
            '/proc/sys/kernel/random/boot_id').read_text().strip()
    except Exception as error:
        result['installation_context'] = {'error': redact(error)}
    for name in ('runtime-attestation.json', 'api.sock', 'host-proxy.json'):
        try:
            path = core.safe(runtime / name, True)
            meta = path.lstat()
            result['runtime_files'][name] = {'mode': oct(meta.st_mode), 'mtime_ns': meta.st_mtime_ns}
        except Exception as error:
            result['runtime_files'][name] = {'error': redact(error)}
    result['interpretation'] = 'HTTP204 alone is not process verification; file tails may predate this boot. Journal visibility depends on existing jwk access.'
    return result


def original_health(post_disconnect):
    _, launcher = original_receipt()
    spec = importlib.util.spec_from_file_location('installed_original_B_runtime', launcher)
    original = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = original
    spec.loader.exec_module(original)
    original.identity('node-b')
    return original.health(types.SimpleNamespace(node='node-b', post_disconnect=post_disconnect))


def combined_health(post_disconnect=False):
    phase = 'B_original_runtime_health'
    old = None
    try:
        print('PHASE=' + phase, flush=True)
        old = original_health(post_disconnect)
        phase = 'B_modified_runtime_health'
        print('PHASE=' + phase, flush=True)
        result = NORMAL_HEALTH(post_disconnect)
        result['original_runtime_verification'] = old
        return result
    except Exception as error:
        print('PHASE=B_both_services_failure_diagnostics', flush=True)
        return {'status': 'STOPPED_B_UB_HEALTH', 'failed_phase': phase, 'error': redact(error),
                'diagnostics_revision': 'b-both-services-v2',
                'original_runtime_verification': old,
                'modified_full_health_attempted': phase == 'B_modified_runtime_health',
                'services': {
                    'original': service_diagnostics(core.BASE, core.ROOT / 'r/node-b', core.OLD_UNIT, 18080),
                    'modified': service_diagnostics(core.D, core.RUNTIME, core.UNIT, 18081)},
                'next_action': 'RETURN_REPORT_NO_REINSTALL_OR_RESTART', 'SDK_called': False}


core.stage_launcher = stage_b_launcher
core.health = combined_health


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['prepare']:
            rc = prepare()
        else:
            if sys.argv[1:2] == ['install']:
                core.baseline = original_for_install
            rc = core.main()
            if sys.argv[1:2] == ['install'] and rc == 0:
                text_path = HERE / 'start_b_both_REVIEW_ONLY.txt'
                text = text_path.read_bytes()
                if hashlib.sha256(text).hexdigest() != ROOT_TEXT_SHA256:
                    raise ValueError('Reviewed root text differs; installation retained, no root text executed')
                print('REVIEW_SCOPE: B only; User=jwk; process kvm/aenv; CAP_SYS_ADMIN/CAP_NET_ADMIN; private namespaces.')
                print('Capabilities are not confined to /home. Keep active original unit. No host/device/account changes.')
                print('BEGIN_REVIEWED_ROOT_COMMANDS_COPY_BODY_ONLY')
                print(text.decode()[text.decode().index('/bin/bash --noprofile'):].rstrip())
                print('END_REVIEWED_ROOT_COMMANDS_COPY_BODY_ONLY')
    except BaseException as error:
        print('BEGIN_RETURN_REPORT')
        print(json.dumps({'status': 'STOPPED_B_SERVICE_ENTRY_PRESERVE_FILES',
                          'error_type': type(error).__name__,
                          'error': re.sub(r'e2b_[A-Za-z0-9._~-]+', '[REDACTED]', str(error)),
                          'SDK_called': False, 'root_or_service_action_attempted': False}, indent=2))
        print('END_RETURN_REPORT')
        rc = 1
    raise SystemExit(rc)
