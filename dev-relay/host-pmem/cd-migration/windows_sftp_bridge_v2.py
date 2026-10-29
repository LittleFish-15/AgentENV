"""Run on the separate user-operated Windows. Fixed private manifest, SFTP only."""
import base64
import csv
import getpass
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

CONTROL = 'LittleFish-15/AgentENV-relay-control'
RESULTS = 'LittleFish-15/AgentENV-relay-results'
CONTROL_ID = 1438089258
RESULT_ID = 1438089386
SESSION = 'relay-20261029-0d032371'
PLAN_PATH = 'windows/' + SESSION + '/sftp-plan-v1.json'
ROOT = Path('E:/AgentTrans') / SESSION


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise RuntimeError('GitHub credential redirect refused')


def api(method, path, token, value=None):
    raw = None if value is None else json.dumps(value).encode()
    request = urllib.request.Request('https://api.github.com' + path, data=raw, method=method,
        headers={'Authorization': 'Bearer ' + token, 'User-Agent': 'AgentENV-Windows-SFTP',
                 'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json'})
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=60) as response:
            return response.status, json.loads(response.read(2 * 1024**2))
    except urllib.error.HTTPError as error:
        raise RuntimeError('GitHub operation failed HTTP ' + str(error.code)) from None
    except urllib.error.URLError:
        raise RuntimeError('GitHub network unavailable; credential details withheld') from None


def private_repo(name, expected, token):
    _, row = api('GET', '/repos/' + name, token)
    need(row.get('private') is True and row.get('id') == expected, 'Private repository identity differs')


def sha_file(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024**2), b''):
            h.update(chunk)
    return h.hexdigest()


def quote(value):
    need(isinstance(value, str) and value and not any(c in value for c in ('"', '\\', '\n', '\r', '\0')),
         'Unsafe SFTP path')
    return '"' + value + '"'


def validate(plan):
    need(plan['sessionId'] == SESSION and plan['version'] == 1, 'Plan session differs')
    need(time.time() < plan['expiresAtUnix'], 'Windows transfer plan expired; request a refreshed plan')
    need(set(plan['nodes']) == {'node-a', 'node-c', 'node-d'}, 'Node list differs')
    for node in plan['nodes'].values():
        need(re.fullmatch(r'[0-9.]+', node['address']) and 1 <= node['port'] <= 65535, 'Invalid fixed endpoint')
        need(node['user'] == 'jwk' and re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/=]+', node['hostPublicKey']),
             'Unexpected account or host public key')
    seen = set(); total = 0
    for item in plan['objects']:
        need(re.fullmatch('[0-9a-f]{64}', item['sha256']) and item['sha256'] not in seen, 'Invalid object identity')
        seen.add(item['sha256'])
        need(type(item['bytes']) is int and 0 < item['bytes'] <= 4 * 1024**3, 'Object size differs')
        total += item['bytes']
        p = PurePosixPath(item['sourcePath'])
        need(p.is_relative_to('/home/jwk/agent') and '..' not in p.parts, 'Source path outside selected workspace')
        quote(item['sourcePath'])
        need(set(item['receivers']) <= {'node-c', 'node-d'} and item['receivers'], 'Unknown receiver')
    need(1 <= len(seen) <= 128 and total <= 8 * 1024**3, 'Manifest bound differs')


def private_workspace():
    need(os.name == 'nt' and ROOT.drive.upper() == 'E:', 'Run on the intermediary Windows with E: drive')
    ROOT.parent.mkdir(exist_ok=True)
    need(not ROOT.parent.is_symlink(), 'Intermediary directory redirected')
    if not ROOT.exists():
        ROOT.mkdir()
        command = subprocess.run(['whoami', '/user', '/fo', 'csv', '/nh'], capture_output=True, text=True, check=True)
        sid = list(csv.reader(io.StringIO(command.stdout)))[0][-1]
        need(re.fullmatch(r'S-1-[0-9-]+', sid), 'Cannot determine current Windows SID')
        subprocess.run(['icacls', str(ROOT), '/inheritance:r', '/grant:r', '*' + sid + ':(OI)(CI)F',
                        '*S-1-5-18:(OI)(CI)F'], check=True, stdout=subprocess.DEVNULL)
        (ROOT / 'workspace-owner.json').write_text(json.dumps({'sid': sid, 'sessionId': SESSION}))
    need(not ROOT.is_symlink() and (ROOT / 'workspace-owner.json').is_file(), 'Unattributed existing workspace preserved')
    for name in ('objects', 'batches', 'receipts'):
        path = ROOT / name
        path.mkdir(exist_ok=True)
        need(not path.is_symlink(), 'Workspace child redirected')


def run_sftp(node_id, node, commands, run_id):
    if not commands:
        return
    alias = 'aenv-windows-' + node_id
    known = ROOT / 'batches' / (run_id + '-' + node_id + '.known_hosts')
    known.write_text(alias + ' ' + node['hostPublicKey'] + '\n', encoding='ascii')
    batch = ROOT / 'batches' / (run_id + '-' + node_id + '.sftp')
    batch.write_text('\n'.join(commands + ['bye']) + '\n', encoding='utf-8')
    executable = shutil.which('sftp.exe')
    need(executable, 'OpenSSH SFTP client is missing')
    argv = [executable, '-F', 'NUL', '-P', str(node['port']), '-o', 'BatchMode=no',
            '-b', str(batch), '-o', 'PreferredAuthentications=keyboard-interactive,password',
            '-o', 'PubkeyAuthentication=no', '-o', 'NumberOfPasswordPrompts=1',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'HostKeyAlias=' + alias,
            '-o', 'HostKeyAlgorithms=ssh-ed25519', '-o', 'UserKnownHostsFile=' + known.as_posix(),
            '-o', 'GlobalKnownHostsFile=NUL', '-o', 'ConnectTimeout=20',
            '-o', 'ServerAliveInterval=20', '-o', 'ServerAliveCountMax=3',
            'jwk@' + node['address']]
    print('SFTP ' + node_id + ': enter this Linux node jwk password in the SSH prompt (not the Windows domain password).', flush=True)
    result = subprocess.run(argv, timeout=7200)
    need(result.returncode == 0, 'SFTP ' + node_id + ' failed; partial files preserved, do not rerun blindly')


def transfer(plan, run_id, report):
    need(shutil.disk_usage(ROOT).free >= sum(x['bytes'] for x in plan['objects']) + 1024**3,
         'At least selected bytes plus 1 GiB headroom required')
    downloads = []
    for item in plan['objects']:
        obj = ROOT / 'objects' / item['sha256']
        partial = obj.with_suffix('.partial')
        need(not obj.is_symlink() and not partial.exists(), 'Prior partial or redirected object preserved; reconcile first')
        if obj.exists():
            need(obj.stat().st_size == item['bytes'] and sha_file(obj) == item['sha256'], 'Existing local object content differs')
        else:
            downloads.append('get ' + quote(item['sourcePath']) + ' ' + quote(partial.as_posix()))
    run_sftp('node-a', plan['nodes']['node-a'], downloads, run_id)
    for item in plan['objects']:
        obj = ROOT / 'objects' / item['sha256']; partial = obj.with_suffix('.partial')
        if partial.exists():
            need(partial.stat().st_size == item['bytes'] and sha_file(partial) == item['sha256'], 'Downloaded object SHA/length differs')
            partial.rename(obj)
        need(obj.exists(), 'Selected object missing after source transfer')
    report['windowsObjectsHashVerified'] = len(plan['objects'])
    report['windowsUniqueBytesVerified'] = sum(x['bytes'] for x in plan['objects'])
    for node_id in ('node-c', 'node-d'):
        node = plan['nodes'][node_id]
        staging = node['stagingDirectory'] + '/' + run_id
        commands = ['mkdir ' + quote(staging)]
        for item in plan['objects']:
            if node_id in item['receivers']:
                commands.append('put ' + quote((ROOT / 'objects' / item['sha256']).as_posix())
                                + ' ' + quote(staging + '/' + item['sha256']))
        run_sftp(node_id, node, commands, run_id)
        report['uploadedStaging'][node_id] = staging
    report['status'] = 'WINDOWS_SFTP_UPLOADED_AWAITING_LINUX_INDEPENDENT_HASH_CHECK'


def main():
    need(sys.stdin.isatty(), 'Run in an interactive Windows PowerShell terminal')
    private_workspace()
    print('Use the two existing dedicated GitHub relay tokens; inputs are hidden and never saved.')
    control_token = getpass.getpass('Control repository READ token: ').strip()
    results_token = getpass.getpass('Results repository WRITE token: ').strip()
    need(control_token and results_token and control_token != results_token, 'Two distinct dedicated tokens are required')
    private_repo(CONTROL, CONTROL_ID, control_token); private_repo(RESULTS, RESULT_ID, results_token)
    _, content = api('GET', '/repos/' + CONTROL + '/contents/' + PLAN_PATH + '?ref=main', control_token)
    need(content.get('type') == 'file' and content.get('encoding') == 'base64', 'Private plan type differs')
    raw = base64.b64decode(content['content'], validate=False)
    need(len(raw) <= 256 * 1024, 'Plan size exceeds bound')
    plan = json.loads(raw); validate(plan)
    run_id = 'win-' + uuid.uuid4().hex
    report = {'version': 1, 'sessionId': SESSION, 'runId': run_id, 'planSha256': hashlib.sha256(raw).hexdigest(),
              'status': 'STARTED', 'uploadedStaging': {}, 'windowsObjectsHashVerified': 0,
              'linuxContentAccepted': False, 'SDK_called': False, 'servicesChanged': False, 'moduleChanged': False}
    try:
        transfer(plan, run_id, report)
    except Exception as error:
        report.update(status='WINDOWS_SFTP_STOPPED_PRESERVE_FILES', reason=str(error))
    report_raw = (json.dumps(report, indent=2) + '\n').encode()
    receipt = ROOT / 'receipts' / (run_id + '.json'); receipt.write_bytes(report_raw)
    # Unique immutable receipt path; failure never overwrites a prior run.
    api('PUT', '/repos/' + RESULTS + '/contents/windows/' + SESSION + '/' + run_id + '.json', results_token,
        {'message': 'Windows SFTP transfer receipt ' + run_id, 'branch': 'main',
         'content': base64.b64encode(report_raw).decode()})
    print(report['status']); print('Private receipt uploaded. Local receipt: ' + str(receipt))
    if report['status'].startswith('WINDOWS_SFTP_STOPPED'):
        raise SystemExit(1)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('WINDOWS_BRIDGE_STOPPED: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
