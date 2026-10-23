"""Read-only, time-bounded observation of this one repaired Runtime cohort.

No service management, Guest mutation, SDK, cache eviction, PFN export, shell
or arbitrary command execution. All executable code comes from the fixed entry.
"""
import hashlib, json, os, re, signal, stat, time, uuid
from pathlib import Path


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def write_json_at(directory_fd, name, value):
    need(name in ('observer-live.json', 'observer-latest.json', 'observer-return.json'), 'Output outside observer scope')
    temporary = name + '.' + uuid.uuid4().hex + '.tmp'
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=directory_fd)
    try:
        os.fchown(fd, 1204, 1205)
        with os.fdopen(fd, 'wb') as stream:
            fd = None
            stream.write((json.dumps(value) + '\n').encode())
            stream.flush();os.fsync(stream.fileno())
        os.replace(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        if fd is not None:
            os.close(fd)


def request_contract(request, plan):
    need(request.get('version') == 1 and request.get('observerRunId') == plan['observerRunId'] and
         request.get('runtimeContext') == plan['runtimeContext'], 'Observation request identity differs')
    ids = request.get('sandboxIds')
    need(isinstance(ids, list) and len(ids) == len(set(ids)) <= 8 and
         all(isinstance(sid, str) and str(uuid.UUID(sid)) == sid for sid in ids), 'Invalid observation Guest set')
    need(re.fullmatch('[0-9a-f]{32}', request.get('runId', '')) is not None, 'Invalid run ID')
    need(request.get('phase') in ('before_restore', 'lifecycle_transition', 'before_replay',
                                'replay_window', 'after_replay', 'owner_finished'), 'Unknown observation phase')
    stamp = request.get('monotonic')
    need(type(stamp) in (int, float) and 0 <= time.monotonic() - stamp <= 900,
         'Owner observation request expired')
    jobs = request.get('jobs')
    need(isinstance(jobs, list) and len(jobs) <= 8, 'Observation job set exceeds bound')
    return ids


def provider_observation(rt, observer, unit):
    try:
        fields = rt.unit_fields(unit)
        need(fields.get('User') == fields.get('Group') == 'jwk' and fields.get('ActiveState') == 'active',
             'Owned file provider not active')
        pid = int(fields['MainPID']);need(pid > 1, 'Provider PID absent')
        ticks = rt.ticks(pid)
        result = {'available': True, 'pid': pid, 'startTicks': ticks,
                  'wholeProcess': observer.whole_process_metrics(pid, ticks),
                  'cgroup': observer.cgroup_memory(pid, ticks),
                  'backingSource': 'host-pagecache', 'experimentUBAllocations': 0,
                  'wholeMachineUBPhysicalChargeBytes': None}
        need(rt.ticks(pid) == ticks and rt.unit_fields(unit)['MainPID'] == str(pid), 'Provider changed during sample')
        return result
    except (OSError, ValueError, RuntimeError) as error:
        return {'available': False, 'errorType': type(error).__name__}


def run(scope, plan_sha):
    rt, observer = scope['module']('four_runtime'), scope['module']('dsec_observer')
    memory = scope['module']('dsec_memory_cache')
    work, deployment = scope['WORK'], scope['D']
    need(isinstance(plan_sha, str) and re.fullmatch('[0-9a-f]{64}', plan_sha), 'Explicit observation plan hash required')
    raw = rt.read(work / 'observer-plan.json')
    need(hashlib.sha256(raw).hexdigest() == plan_sha, 'Observation plan changed')
    plan = json.loads(raw)
    need(plan.get('entrySha256') == hashlib.sha256(Path(scope['__file__']).read_bytes()).hexdigest()
         and plan.get('coreCommit') == scope['CORE'] and plan.get('maxSeconds') == 10800
         and plan.get('maxGuests') == 8, 'Unexpected observation plan scope')
    api, context, _ = scope['runtime_contract'](rt)
    need(context == plan['runtimeContext'], 'Observer Runtime differs')
    seed, _, _, selection_sha = scope['input_contract'](rt)
    need(selection_sha == plan['sourceSelectionSha256'], 'Observer selection differs')
    pins = observer.pin_base_files([scope['INPUTS'] / f'case-{i}/raw/rootfs.ext4' for i in range(4)])
    need(pins == plan['baseFiles'], 'Observer base identities changed')
    lowers = sorted({Path(layer['path']) for image in seed['images'] for layer in image['layers']})
    need([str(path) for path in lowers] == plan['allowedLowers'], 'Observer lower allowlist differs')
    memory_pins = memory.memory_lower_inventory(rt, observer, deployment, rt.load(work / 'templates.json')['templates'])
    need(memory_pins == plan['memoryFiles'], 'Observer committed memory lower inventory differs')
    need(type(plan.get('ownerPid')) is int and plan['ownerPid'] > 1 and
         rt.ticks(plan['ownerPid']) == plan['ownerTicks'], 'Owner controller process changed')
    need(work.resolve(strict=True) == work and work.stat().st_uid == 1204, 'Observer work directory differs')
    need(not any((work / name).exists() for name in ('root-observations.jsonl', 'observer-live.json',
             'observer-latest.json', 'observer-return.json')), 'Previous observer evidence preserved; no blind restart')
    directory = os.open(work, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    journal = None
    final = {'status': 'READONLY_OBSERVER_STOPPED', 'planSha256': plan_sha,
             'observerRunId': plan['observerRunId'], 'SDK_called': False, 'servicesChanged': False,
             'Guest_mutations': False, 'rawPFNsExported': False, 'sampleCount': 0}
    stopped = False
    def cancel(*_):
        nonlocal stopped
        stopped = True
    for name in ('SIGTERM', 'SIGINT', 'SIGHUP'):
        signal.signal(getattr(signal, name), cancel)
    try:
        fd = os.open('root-observations.jsonl', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=directory)
        os.fchown(fd, 1204, 1205)
        journal = os.fdopen(fd, 'w', encoding='utf-8')
        began, heavy_at = time.monotonic(), 0
        last_phase, last_ids, known = None, None, {}
        own_pid, own_ticks = os.getpid(), rt.ticks(os.getpid())
        while not stopped and time.monotonic() - began < 10800:
            request = rt.load(work / 'observation-request.json')
            ids = request_contract(request, plan)
            need(rt.ticks(api.pid) == api.ticks, 'Observed Runtime exited/reused')
            # No API key or workloads are ever copied into the observation file.
            jobs = [{key: row.get(key) for key in ('sandboxId', 'templateIndex', 'slot', 'state')}
                    for row in request['jobs']]
            now = time.monotonic()
            sample = {'startNs': time.time_ns(), 'observerRunId': plan['observerRunId'],
                      'runId': request['runId'], 'phase': request['phase'], 'host': observer.host_observation(),
                      'runtimeCharge': observer.cgroup_memory(api.pid, api.ticks),
                      'collector': observer.whole_process_metrics(own_pid, own_ticks),
                      'ownerController': observer.whole_process_metrics(plan['ownerPid'], plan['ownerTicks']),
                      'jobStatesAtCollectionStart': jobs, 'jobStatesAtCollectionEnd': jobs,
                      'jobStatesNotAtomicallyObserved': True, 'atomicSnapshot': False, 'heavySample': False}
            heavy = now >= heavy_at or (request['phase'] != last_phase and
                request['phase'] in ('before_replay', 'after_replay', 'owner_finished')) or ids != last_ids
            if heavy:
                api.stable()
                sample['ram'] = observer.collect_ram(deployment, api.pid, api.ticks, ids,
                    expected_bytes={sid: 4096 * 1024**2 for sid in ids}, pinned_files=pins, allowed_lowers=lowers,
                    device_module=memory)
                sample['hostPmemFiles'] = observer.base_file_cache(pins)
                sample['memoryLowerFiles'] = observer.base_file_cache(memory_pins)
                sample['memoryLowerFiles']['scope'] = 'committed_snapshot_memory_lower_files_whole_residency_not_access'
                sample['memoryDevices'] = memory.device_cache(sample['ram'].get('guests', []), observer)
                sample['runtimeServices'] = memory.service_processes(api.pid, api.ticks,
                    {g['pid'] for g in sample['ram'].get('guests', []) if g.get('pid')}, observer)
                sample['provider'] = provider_observation(rt, observer, scope['PROVIDER'])
                sample['runtimeProcess'] = observer.whole_process_metrics(api.pid, api.ticks)
                sample['heavySample'] = True
                known = {row['sandboxId']: row for row in sample['ram'].get('guests', [])
                         if row.get('pid') and row.get('startTicks')}
                heavy_at = time.monotonic() + 15
            else:
                guests = []
                for sid in ids:
                    row = known.get(sid)
                    if row is None:
                        guests.append({'sandboxId': sid, 'available': False})
                    else:
                        guests.append({'sandboxId': sid, 'pid': row['pid'], 'startTicks': row['startTicks'],
                            'wholeProcess': observer.whole_process_metrics(row['pid'], row['startTicks']),
                            'guestRam': {'available': False, 'reason': 'Heavy VMA scan not scheduled this cycle'}})
                sample['ram'] = {'available': set(known) == set(ids), 'guests': guests,
                                  'scope': 'light_process_metrics_only'}
            last_phase, last_ids = request['phase'], list(ids)
            sample['endNs'] = time.time_ns()
            latest = rt.load(work / 'observation-request.json')
            if latest.get('runId') == request['runId']:
                sample['jobStatesAtCollectionEnd'] = [{key: row.get(key) for key in
                    ('sandboxId', 'templateIndex', 'slot', 'state')} for row in latest.get('jobs', [])]
            need(journal.tell() < 512 * 1024**2, 'Observer output budget exhausted')
            journal.write(json.dumps(sample) + '\n');journal.flush()
            write_json_at(directory, 'observer-latest.json', sample)
            write_json_at(directory, 'observer-live.json', {'planSha256': plan_sha,
                'observerRunId': plan['observerRunId'], 'monotonic': time.monotonic(),
                'pid': own_pid, 'ticks': own_ticks})
            final['sampleCount'] += 1
            if request['phase'] == 'owner_finished':
                final['status'] = 'READONLY_OBSERVER_OWNER_FINISHED'
                break
            time.sleep(1)
        else:
            final['reason'] = 'Signal received or bounded observation deadline reached'
    except Exception as error:
        final.update(errorType=type(error).__name__, reason=str(error)[:500] if isinstance(error, RuntimeError) else 'Observation unavailable')
    finally:
        if journal is not None:
            journal.flush();os.fsync(journal.fileno());journal.close()
        write_json_at(directory, 'observer-return.json', final)
        os.close(directory)
    print(json.dumps(final, indent=2))
    return 0 if final['status'] == 'READONLY_OBSERVER_OWNER_FINISHED' else 1
