"""Scoped failed-run recovery and separate delete-fix deployment; no Guest test.

The old pair journal is never rewritten as a successful DELETE. Only the exact
old dedicated unit and its verified host proxy receive SIGTERM. Providers stay.
"""
import argparse, base64, hashlib, json, os, platform, re, select, shutil, signal, stat, sys, time, types, uuid, zlib
from pathlib import Path

ROOT = Path('/home/jwk/agent')
OLD = ROOT / 'deployments/agentenv-direct-ub-guest-v1'
PAIR = OLD / 'acceptance/direct-pair-v1'
RECOVERY = PAIR / 'deletefix-recovery-v1'
RUN = 'ca0e30a36541483eaa26ff38ead95f8f'


def need(ok, why):
    if not ok:
        raise RuntimeError(why)


def module(path, pin, name):
    need(path.resolve(strict=True) == path and path.is_relative_to(ROOT), 'Code path redirected')
    raw = path.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == pin, 'Pinned code changed')
    m = types.ModuleType(name); m.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), m.__dict__)
    return m


def checkpoint(value):
    temp = RECOVERY / ('progress-' + uuid.uuid4().hex + '.tmp')
    with temp.open('xb') as stream:
        stream.write((json.dumps(value, indent=2) + '\n').encode()); stream.flush(); os.fsync(stream.fileno())
    os.chmod(temp, 0o600)
    os.replace(temp, RECOVERY / 'progress.json')
    fd = os.open(RECOVERY, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def expected_phase(node, life, phase, sid):
    need(life['runId'] == RUN and life['sandboxIds'] == [sid], 'Unexpected old cohort')
    if node == 'a':
        requests = life['openRequests']
        need(phase['phase'] == 'a-written' and phase.get('pending', {}).get('phase') == 'release-a'
             and life['outcomeUncertain'] is True
             and phase.get('error', {}).get('reason') == 'Delete request not confirmed'
             and len(requests) == 1 and requests[0]['kind'] == 'delete'
             and requests[0]['route'] == '/sandboxes/' + sid, 'Not the known A pending delete')
    else:
        need(phase['phase'] == 'peer-isolated' and 'pending' not in phase and 'error' not in phase
             and life['openRequests'] == [] and life['outcomeUncertain'] is False,
             'Unexpected B continuation state')


def owned_device_ids(log_text, sid, root_device, template):
    text = re.sub(r'\x1b\[[0-9;]*m', '', log_text)
    key = str(OLD / 'state/snapshot-local-cache/runtime' / template / 'memory/image.json')
    memory = set()
    for line in text.splitlines():
        if sid in line and 'created or acquired shared read-only ublk device' in line and 'key=' + key in line:
            match = re.search(r'\bdev_id=(\d+)\b', line)
            need(match is not None, 'Memory device log lacks identity')
            memory.add(int(match[1]))
    match = re.fullmatch(r'/dev/ublkb(\d+)', root_device)
    need(match is not None and len(memory) == 1, 'Cannot identify the two owned devices')
    root_id = int(match[1]); need(root_id not in memory, 'Device roles alias')
    return {root_id, *memory}


def daemon_devices(pid):
    found = set()
    for fd in (Path('/proc') / str(pid) / 'fd').iterdir():
        try:
            name = os.readlink(fd)
            match = re.fullmatch(r'/dev/ublkc(\d+)', name)
            if match:
                current = fd.stat(); named = Path(name).stat()
                need(stat.S_ISCHR(current.st_mode) and current.st_rdev == named.st_rdev, 'Daemon device FD changed')
                found.add(int(match[1]))
        except FileNotFoundError:
            continue
    return found


def group_pids(group):
    found=[]
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit(): continue
        try:
            groups=[line.split(':',2)[2] for line in (proc/'cgroup').read_text().splitlines()]
            if any(value==group or value.startswith(group+'/') for value in groups): found.append(int(proc.name))
        except (FileNotFoundError,ProcessLookupError): continue
    return sorted(found)


def devices_absent(ids):
    return all(not path.exists() and not path.is_symlink() for dev_id in ids for path in (
        Path('/dev') / ('ublkb' + str(dev_id)), Path('/dev') / ('ublkc' + str(dev_id)),
        Path('/sys/class/ublk-char') / ('ublkc' + str(dev_id))))


def exited(fd):
    poll = select.poll(); poll.register(fd, select.POLLIN)
    return bool(poll.poll(0))


def wait_owned_exit(fds, ids, cgroup):
    deadline = time.monotonic() + 90
    while not (all(exited(fd) for name, fd in fds.items() if name != 'proxy')
               and devices_absent(ids) and not group_pids(cgroup)):
        need(time.monotonic() < deadline, 'Old processes/devices not confirmed gone; no forced kill or deployment')
        time.sleep(0.25)


def install_owner_code(path, raw):
    need(path.parent.resolve(strict=True) == path.parent and not path.is_symlink(), 'Stage path redirected')
    if path.exists():
        meta = path.stat()
        need(meta.st_uid == 1204 and stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1
             and path.read_bytes() == raw, 'Prior staged code differs')
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); os.fchown(stream.fileno(), 1204, 1205); stream.flush(); os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--run', action='store_true'); args = parser.parse_args()
    if not args.run:
        print(json.dumps({'status': 'PLAN_ONLY', 'scope': 'stop only verified old dedicated unit/proxy, verify owned devices and local UB leases gone, stage separate fixed-daemon Runtime on same port; preserve old failure'})); return 0
    need(sys.platform == 'linux' and os.getuid() == os.geteuid() == 0, 'Root Linux execution required')
    node = {'server1': 'a', 'agent1': 'b'}.get(platform.node()); need(node is not None, 'Wrong node')
    os.umask(0o077)
    need(hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'), 'Race-safe process signalling required')
    ready = module(ROOT / 'AB_actual_ub_guest_ready_v1.py', '145ddd8b86c3cb8a1d1cb61278b01cbf0039668827a83e340e550f11e7c53c30', 'retained_ready')
    controller = module(ROOT / 'actual_guest_pair_continue_v2.py', '6c01a15e36a056b29a400e52f33f38981ff0abf3ca939185e6a4074dd9fda1fa', 'retained_controller')
    raw = zlib.decompress(base64.b64decode(DEPLOY_Z64, validate=True)); need(hashlib.sha256(raw).hexdigest() == DEPLOY_SHA, 'New deployment code differs')
    deploy_path = ROOT / 'AB_deploy_direct_deletefix_v1.py'
    deploy = types.ModuleType('fixed_deletefix_deployment'); deploy.__file__ = str(deploy_path)
    exec(compile(raw, str(deploy_path), 'exec'), deploy.__dict__)
    import fcntl
    need(PAIR.resolve(strict=True) == PAIR and PAIR.stat().st_uid == 0, 'Pair directory changed')
    lock = os.open(PAIR / 'run.lock', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    fds = {}; made = False
    result = {'status': 'RECOVERY_PREFLIGHT', 'node': node, 'normalDeletePassed': False,
              'oldPairLifecycleAccepted': False, 'oldJournalRewritten': False, 'providerRetired': False,
              'SDKAllocationCalled': False, 'kernelModuleOrMemoryTopologyChanged': False, 'newGuestCreated': False,
              'servicesChangeAttempted': False,
              'automaticRollback': False, 'signalIntents': []}
    try:
        meta = os.fstat(lock); need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and meta.st_nlink == 1, 'Pair lock changed')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        need(not RECOVERY.exists() and not RECOVERY.is_symlink(), 'Prior recovery attempt preserved; do not repeat')
        docs = {name: controller.document(PAIR / name) for name in ('report.json', 'state.json', 'pair-phases.json')}
        origin, life, phase = [docs[name][0] for name in ('report.json', 'state.json', 'pair-phases.json')]
        need(origin['node'] == node and origin['pairRunId'] == RUN, 'Wrong original pair')
        sid = origin['sandboxId']; expected_phase(node, life, phase, sid)
        runtime = ready.ReadyRun(); need(runtime.n == node and runtime.server == origin['serverIdentity']
            and runtime.provider == origin['provider'], 'Old Runtime/provider incarnation changed')
        runtime.guard()
        need(runtime.api.cgroup == '/system.slice/' + runtime.m.UNIT, 'Unexpected unit cgroup')
        status, body = runtime.api.call('GET', '/sandboxes/' + sid)
        need(status == 200 and body['sandboxID'] == sid and body['metadata']['cow_batch'] == RUN, 'Old Guest ownership differs')
        status, inventory = runtime.api.call('GET', '/v2/sandboxes?limit=1')
        need(status == 200 and isinstance(inventory, list) and all(row.get('sandboxID') == sid for row in inventory), 'Additional or unknown inventory')
        fcs = ready.find_processes(Path(origin['binaries']['firecracker']['path']), runtime.api.cgroup)
        need(fcs == [] or fcs == [origin['binding']['fcIdentity']], 'Unexpected FC in dedicated unit')
        if node == 'a': need(not fcs, 'A FC is unexpectedly live; preserve it')
        daemon = ready.process(origin['binding']['daemonIdentity']['pid'], Path(origin['binding']['daemonIdentity']['executable']), runtime.api.cgroup)
        need(daemon == origin['binding']['daemonIdentity'], 'Old daemon changed')
        ids = owned_device_ids(runtime.deploy.read(OLD / 'logs/server.log', 4 * 1024**2).decode('utf-8', 'replace'), sid,
                               origin['binding']['rootfsDevice'], runtime.deploy.TEMPLATE)
        need(daemon_devices(daemon['pid']) == ids, 'Daemon owns additional/missing devices; do not stop it')
        root_meta = Path(origin['binding']['rootfsDevice']).stat()
        need(stat.S_ISBLK(root_meta.st_mode) and (os.major(root_meta.st_rdev), os.minor(root_meta.st_rdev)) ==
             (origin['binding']['rootfsDeviceMajor'], origin['binding']['rootfsDeviceMinor']), 'Rootfs device changed')
        need(runtime.provider['providerProcess']['pid'] not in group_pids(runtime.api.cgroup), 'Provider unexpectedly belongs to old Runtime unit')
        provider_before = controller.provider_status(runtime)
        need(provider_before['activePayloadResponses'] == 0, 'Provider has an in-flight payload; no stop')
        proxy = runtime.deploy.load(runtime.deploy.location(node)[0] / 'host-proxy.json')
        proxy_identity = runtime.m.process_identity(proxy['pid'])
        need(proxy_identity['start_ticks'] == proxy['start_ticks'] and proxy_identity['uid'] == [1204] * 4
             and runtime.m.owns_listener(proxy['pid']), 'Old host proxy identity differs')
        new_runtime, new_fc, new_unit = deploy.location(node)
        need(all(not path.exists() and not path.is_symlink() for path in (deploy.D, new_runtime, new_fc)), 'New deployment paths already exist')
        need(runtime.m.properties(new_unit).get('LoadState') == 'not-found', 'New unit already exists')
        # Preserve small private upper/config bytes before application shutdown
        # can remove its TempDir. This is evidence, not a restorable VM snapshot.
        need(set(origin['binding']['upper'])=={'data','index'},'Unexpected upper evidence fields')
        evidence_paths={'image.json':Path(origin['binding']['imageConfigPath'])}
        evidence_paths.update({'upper.'+name:Path(row['path']) for name,row in origin['binding']['upper'].items()})
        fc_directory=Path(origin['binding']['imageConfigPath']).parent.parent
        evidence={}
        for name,path in evidence_paths.items():
            need(path.is_relative_to(fc_directory) and path.resolve(strict=True)==path,'Old upper/config redirected')
            evidence[name]=runtime.deploy.read(path,64*1024**2)
        need(hashlib.sha256(evidence['image.json']).hexdigest()==origin['binding']['imageConfigSha256'],'Old rootfs configuration changed')
        need(sum(map(len,evidence.values()))<=128*1024**2,'Old evidence exceeds bounded copy budget')
        deploy.candidate_artifacts(node)  # Hash and build evidence before any stop.
        need(shutil.disk_usage(ROOT).free >= 8 * 1024**3, 'Insufficient staging space; no cleanup')
        for name, identity in [('server', runtime.server), ('daemon', daemon), *([('fc', fcs[0])] if fcs else [])]:
            fds[name] = os.pidfd_open(identity['pid'])
            need(ready.process(identity['pid'], Path(identity['executable']), runtime.api.cgroup) == identity, 'Process changed before pidfd use')
        fds['proxy'] = os.pidfd_open(proxy['pid'])
        need(runtime.m.process_identity(proxy['pid'])['start_ticks'] == proxy['start_ticks'], 'Proxy changed before pidfd use')
        result.update(oldUnit=runtime.m.UNIT, oldServer=runtime.server, oldDaemon=daemon, oldFCs=fcs,
                      oldDeviceIds=sorted(ids), providerBefore=provider_before, oldDocumentHashes={k:v[1] for k,v in docs.items()},
                      preservedUnits=runtime.original_units, reusedPort=runtime.definition['apiPort'], newUnit=new_unit)
        RECOVERY.mkdir(mode=0o700); made = True
        for name, row in docs.items():
            with (RECOVERY / ('before-' + name)).open('x') as out: json.dump(row[0], out, indent=2)
        for name,data in evidence.items():
            with (RECOVERY/('before-'+name)).open('xb') as out:
                out.write(data);out.flush();os.fsync(out.fileno())
        result['oldUpperConfigEvidence']={name:{'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()} for name,data in evidence.items()}
        result['restorableGuestSnapshotCreated']=False
        result['servicesChangeAttempted'] = True
        result['signalIntents'].append({'role': 'old-server', 'pid': runtime.server['pid'], 'signal': 'SIGTERM'})
        checkpoint(result); runtime.guard()
        signal.pidfd_send_signal(fds['server'], signal.SIGTERM)
        wait_owned_exit(fds, ids, runtime.api.cgroup)
        result['oldProcessesAndDevicesGone'] = True; result['oldCgroupEmpty'] = True; checkpoint(result)
        if not exited(fds['proxy']):
            need(runtime.m.process_identity(proxy['pid'])['start_ticks'] == proxy['start_ticks']
                 and runtime.m.owns_listener(proxy['pid']), 'Proxy changed after unit exit')
            result['signalIntents'].append({'role': 'old-host-proxy', 'pid': proxy['pid'], 'signal': 'SIGTERM'}); checkpoint(result)
            signal.pidfd_send_signal(fds['proxy'], signal.SIGTERM)
        deadline = time.monotonic() + 10
        while not exited(fds['proxy']):
            need(time.monotonic() < deadline, 'Old proxy exit unconfirmed'); time.sleep(0.2)
        result['oldProxyGone'] = True
        deadline = time.monotonic() + 10
        while True:
            need(runtime.deploy.check_provider(node) == runtime.provider, 'Retained provider changed')
            after = controller.provider_status(runtime)
            if after['activeLeases'] == after['activePayloadResponses'] == 0: break
            need(time.monotonic() < deadline, 'Old local UB readers remain; do not deploy'); time.sleep(0.2)
        need(runtime.deploy.preserve_units(runtime.m, node) == runtime.original_units, 'Unrelated unit changed')
        need(int(runtime.m.properties(runtime.m.UNIT).get('MainPID', '0')) == 0, 'Old unit still has a main process')
        need(all(controller.document(PAIR/name)[1] == row[1] for name,row in docs.items()), 'Old journal changed')
        result.update(providerAfter=after, oldLocalUBReadersZero=True, oldFailureEvidencePreserved=True)
        checkpoint(result)
        install_owner_code(deploy_path, raw)
        result['stageIntent'] = str(deploy.D); checkpoint(result)
        prepared = deploy.as_owner(['/usr/bin/python3', '-I', '-B', str(deploy_path), 'prepare', '--run'], 300)
        (RECOVERY/'prepare.log').write_text(prepared.stdout + prepared.stderr)
        need(prepared.returncode == 0, 'New staging failed; see private prepare.log')
        result['newPrepared'] = True; checkpoint(result)
        result['activationIntent'] = new_unit; checkpoint(result)
        result['activation'] = deploy.activate()
        healthy = deploy.as_owner(['/usr/bin/python3', '-I', '-B', str(deploy_path), 'health', '--run'], 180)
        (RECOVERY/'health.log').write_text(healthy.stdout + healthy.stderr)
        need(healthy.returncode == 0, 'New health failed; preserve new unit and health.log')
        definition = deploy.load(deploy.D/'guest-definition.json')
        need(definition['apiPort'] == runtime.definition['apiPort'], 'API port changed')
        api = runtime.rt.Api(deploy.D, new_unit, definition['apiPort'])
        result['newServer'] = ready.process(api.pid, deploy.D/'bin/server', api.cgroup)
        daemons = ready.find_processes(deploy.D/'bin/uvm-ublk-daemon', api.cgroup)
        need(len(daemons) == 1, 'Expected one new daemon')
        result['newDaemon'] = daemons[0]
        need(runtime.rt.digest_file(deploy.D/'bin/uvm-ublk-daemon') == deploy.CORE_ARTIFACTS['uvm-ublk-daemon']['sha256'], 'Fixed daemon hash differs')
        need(api.call('GET', '/v2/sandboxes?limit=1') == (200, []), 'Unexpected Guest in fresh service')
        need(runtime.deploy.preserve_units(runtime.m,node) == runtime.original_units, 'Unrelated unit changed during deployment')
        need(runtime.deploy.check_provider(node) == runtime.provider, 'Provider changed during deployment')
        need(all(controller.document(PAIR/name)[1] == row[1] for name,row in docs.items()), 'Old journal rewritten')
        result.update(status='SCOPED_OLD_RUNTIME_RECOVERED_DELETEFIX_HEALTHY_NO_GUEST',
                      newDaemonSha256=deploy.CORE_ARTIFACTS['uvm-ublk-daemon']['sha256'],
                      retainedServerSha256=deploy.CORE_ARTIFACTS['server']['sha256'],
                      daemonSourceCommit=deploy.CORE_COMMIT, serverBuildSourceCommit=deploy.SERVER_BUILD_COMMIT,
                      newDeployment=str(deploy.D), ordinaryUserHealthPassed=True, sharedUBObjectsRetained=True,
                      transferForB=deploy.load(deploy.D/'prepare-report.json').get('transferPackage'))
        checkpoint(result)
    except Exception as error:
        result.update(status='STOPPED_SCOPED_DELETEFIX_RECOVERY_PRESERVE_STATE', errorType=type(error).__name__, reason=str(error))
        if made: checkpoint(result)
    finally:
        for fd in fds.values(): os.close(fd)
        os.close(lock)
    print('BEGIN_SCOPED_DELETEFIX_RECOVERY_REPORT'); print(json.dumps(result, indent=2)); print('END_SCOPED_DELETEFIX_RECOVERY_REPORT')
    return 0 if result['status'] == 'SCOPED_OLD_RUNTIME_RECOVERED_DELETEFIX_HEALTHY_NO_GUEST' else 1


if __name__ == '__main__':
    try: raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'status':'STOPPED_SCOPED_DELETEFIX_RECOVERY_UNRECORDED_ERROR','errorType':type(error).__name__,'reason':str(error),'resourcesChanged':None,'automaticRetry':False})); raise SystemExit(1)
