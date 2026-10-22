"""Private-input selection and exact cohort scope; contains no benchmark data."""
import base64
import copy
import hashlib
import json
import re


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def select_four(history, inputs, build):
    need(history.get('validation', {}).get('status') ==
         'COW4_ACCESS_MEASURED_GUESTS_RELEASED_ORIGINAL_RESTORED', 'Four-template reference did not complete')
    need(history['validation'].get('all_cohort_guests_released') is True,
         'Historical cohort cleanup not confirmed')
    jobs = history.get('jobs', [])
    need(len(jobs) == 8 and len({j['sandbox_id'] for j in jobs}) == 8, 'Expected eight reference Guests')
    cases, selected = inputs.get('cohort', {}).get('cases', []), []
    grouped = {}
    for job in sorted(jobs, key=lambda j: j['index']):
        need(job.get('state') == 'REPLAY_COMPLETED', 'Reference replay incomplete')
        grouped.setdefault(job['instance_id'], []).append(job)
    need(len(grouped) == 4, 'Expected four distinct reference templates')
    for instance, pair in grouped.items():
        need(len(pair) == 2 and {j['slot'] for j in pair} == {0, 1}, 'Reference must have two slots per template')
        identity = {(j['template_id'], j['catalog_sha256'], j['replay_sha256']) for j in pair}
        need(len(identity) == 1, 'Reference template/input identities differ within pair')
        template_id, record_sha, replay_sha = identity.pop()
        matches = [c for c in cases if c['instance_id'] == instance]
        prepared = [c for c in build['cases'] if c['instance_id'] == instance]
        need(len(matches) == len(prepared) == 1, 'Missing or ambiguous private input')
        case, original = matches[0], prepared[0]
        need(case['replay_sha256'] == replay_sha and original.get('state') == 'READY'
             and original.get('template_id') == template_id and original.get('catalog_sha256') == record_sha,
             'Existing template or replay differs from historical reference')
        raw = base64.b64decode(inputs['replays'][case['replay_file']], validate=True)
        need(sha(raw) == replay_sha, 'Private replay digest differs')
        trajectory = json.loads(raw).get('trajectory', [])
        actions = []
        for item in trajectory:
            action = item.get('action', '') if isinstance(item, dict) else ''
            if not isinstance(action, str) or not action.strip():
                continue
            if action.strip().lower() in ('submit', 'finish', 'done'):
                break
            actions.append(action)
        # The old planning count may include the terminal submit marker. Actual
        # executed actions must match the successful historical jobs exactly.
        need(actions and all(j['steps_completed'] == len(actions) for j in pair), 'Replay action coverage differs')
        resource = original['resources']
        need(resource['memory_mib'] == 4096 and 1 <= resource['cpu_count'] <= 16,
             'Unexpected reference Guest resources')
        selected.append({'case': copy.deepcopy(case), 'original': copy.deepcopy(original),
                         'replayBase64': base64.b64encode(raw).decode(),
                         'executedStepCount': len(actions),
                         'historicalJobs': copy.deepcopy(pair)})
    need(len({s['original']['template_id'] for s in selected}) == 4, 'Repeated reference template')
    return selected


def scenario_jobs(selected, scenario):
    need(len(selected) == 4 and scenario in ('single-a', 'dual-ab'), 'Invalid scenario')
    nodes = ('node-a',) if scenario == 'single-a' else ('node-a', 'node-b')
    result = []
    for node in nodes:
        for index, selected_case in enumerate(selected):
            for slot in (0, 1):
                result.append({'node': node, 'templateIndex': index, 'slot': slot,
                               'instanceId': selected_case['case']['instance_id'],
                               'replaySha256': selected_case['case']['replay_sha256'],
                               'resources': copy.deepcopy(selected_case['original']['resources'])})
    need(len(result) == (8 if scenario == 'single-a' else 16), 'Incorrect Guest count')
    return result


def source_identity(layers):
    descriptors = []
    for layer in layers:
        need(re.fullmatch(r'sha256:[0-9a-f]{64}', layer.get('digest', ''))
             and type(layer.get('size')) is int and layer['size'] > 0, 'Invalid immutable layer identity')
        descriptors.append({k: layer[k] for k in ('digest', 'size')})
    need(0 < len(descriptors) <= 256, 'Invalid source layer count')
    return 'sha256:' + sha(json.dumps([0, descriptors], separators=(',', ':')).encode())


def source_from_record(record, config, original):
    need(record['id'] == original['template_id'] and record['resources'] == original['resources'],
         'Original record/resource identity differs')
    committed = record['committed']['rootfs_layers']
    need(all(set(layer) == {'Managed'} for layer in committed), 'Only committed local managed layers supported')
    layers = config.get('lowers', [])
    need(0 < len(layers) < len(committed), 'Original OCI source is not a strict snapshot prefix')
    need(not config.get('upper') or not any(config['upper'].get(k) for k in ('data', 'index', 'target')),
         'Writable source config refused')
    for current, captured in zip(layers, committed):
        need({k: current[k] for k in ('digest', 'size')} ==
             {k: captured['Managed'][k] for k in ('digest', 'size')}, 'OCI source differs from captured prefix')
        need(not any(current.get(k) for k in ('ub', 'gzipIndex', 'targetFile', 'targetDigest')),
             'Unsupported mutable/remote layer indirection')
    # Capture layers are intentionally not relabeled as original OCI layers.
    return {'sourceImage': source_identity(layers), 'sourceLayerCount': len(layers),
            'captureOnlyLayerCount': len(committed) - len(layers),
            'scope': 'same_original_OCI_input_new_native_parent_not_old_VM_state'}


def validate_comparison_scope(history, reports):
    """Reject incomplete/mixed cohorts before displaying reference deltas."""
    need({(r['scenario'], r['node']) for r in reports} ==
         {('single-a', 'node-a'), ('dual-ab', 'node-a'), ('dual-ab', 'node-b')}
         and len(reports) == 3, 'Need one single-A and both dual-node reports')
    reference = {j['instance_id']: j['replay_sha256'] for j in history['jobs']}
    for report in reports:
        jobs = report['jobs']
        need(len(jobs) == 8 and len({j['sandboxId'] for j in jobs}) == 8, 'Incomplete per-node cohort')
        need(report.get('ownedGuestsReleased') is True and report.get('outcomeUncertain') is False,
             'Unresolved/new Guest lifecycle')
        for instance, digest in reference.items():
            pair = [j for j in jobs if j['instanceId'] == instance]
            need(len(pair) == 2 and {j['slot'] for j in pair} == {0, 1}
                 and all(j['replaySha256'] == digest and j['state'] == 'REPLAY_COMPLETED' for j in pair),
                 'New replay coverage or input differs')
    return {'historicalReferenceOnly': True, 'controlledABExperiment': False,
            'backgroundWorkloadMayDiffer': True, 'memfileCrossNodeCowAccepted': False,
            'hostLowerAccessResidencyComparable': False, 'globalNetSavingBytes': None}
