"""Read existing original experiment receipts; never rerun the workload.

The caller supplies a private report path and its known SHA. Public code carries
no fixed experiment results, case names, command text or private report paths.
"""
import hashlib, json, re
from pathlib import Path

ORIGINAL = 'ae9c62693839ce7effa2b45df31c0039ae4f9fbc'


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def normalize_events(raw, job):
    rows = [json.loads(line) for line in raw.splitlines()]
    need(len(rows) == job['steps_completed'] <= 2000 and len(rows) > 0, 'Original event count differs')
    result = []
    for index, row in enumerate(rows):
        code = row.get('return_code')
        need(type(row.get('step')) is int and row['step'] == index and
             type(code) is int and 0 <= code <= 255 and code not in (124, 137), 'Original step/exit contract differs')
        started, finished = row.get('started_unix'), row.get('finished_unix')
        need(type(started) in (int, float) and type(finished) in (int, float) and started <= finished,
             'Original command time invalid')
        # The pinned original command() writes an event only after transport0
        # and exactly one Guest exit marker. Do not infer success from stdout.
        result.append({'step': index, 'returnCode': code, 'startedUnix': started, 'finishedUnix': finished,
                       'requestedDelaySeconds': row.get('requested_delay_seconds')})
    need(sum(r['returnCode'] != 0 for r in result) == job['failed_commands'], 'Original nonzero count differs')
    return result


def export(rt, root, report_path, expected_sha):
    report_path = Path(report_path)
    need(report_path.is_absolute() and report_path.name == 'combined-summary.json' and
         report_path.parent.parent == root / 'relay/reports' and
         re.fullmatch('node-a-memory-256-[A-Za-z0-9_-]+', report_path.parent.name), 'Original report outside declared scope')
    need(isinstance(expected_sha, str) and re.fullmatch('[0-9a-f]{64}', expected_sha), 'Explicit original report SHA required')
    raw = rt.read(report_path, 64 * 1024**2)
    need(hashlib.sha256(raw).hexdigest() == expected_sha, 'Original report content changed')
    report = json.loads(raw)
    implementation = report.get('experiment_comparison', {})
    need(implementation.get('base_commit') == ORIGINAL and implementation.get('io64_core_changes_used') is False,
         'Expected actual original256 report, not modified/off control')
    validation = report.get('validation', {})
    need(validation.get('all_cohort_guests_released') is True and validation.get('replay_completed_guests') == 8,
         'Original completed/released receipt required')
    jobs = report.get('jobs')
    need(isinstance(jobs, list) and len(jobs) == 8 and
         sorted(j['index'] for j in jobs) == list(range(8)) and
         len({(j['instance_id'], j['slot']) for j in jobs}) == 8 and
         all(j['state'] == 'REPLAY_COMPLETED' for j in jobs), 'Original cohort incomplete')
    repository = root / 'deployments/agentenv-ae9c626-baseline/state/snapshot-store/repository'
    output = {'revision': 'original-reference-supplement-v1', 'runId': report['run_id'],
              'sourceReportSha256': expected_sha, 'sourceReport': str(report_path),
              'originalCoreCommit': ORIGINAL, 'readOnly': True, 'SDK_called': False,
              'Guest_created': False, 'servicesChanged': False, 'jobs': [], 'errors': []}
    for job in jobs:
        value = {'instanceId': job['instance_id'], 'slot': job['slot'], 'sandboxId': job['sandbox_id'],
                 'originalTemplateId': job['template_id'], 'parentSnapshotId': job['parent_snapshot_id'],
                 'replaySha256': job['replay_sha256'], 'catalogSha256': job['catalog_sha256'],
                 'resources': None, 'events': None, 'eventsSha256': None}
        try:
            path = report_path.parent / 'commands' / ('%03d-events.jsonl' % job['index'])
            data = rt.read(path, 8 * 1024**2)
            value['events'] = normalize_events(data, job)
            value['eventsSha256'] = hashlib.sha256(data).hexdigest()
        except (OSError, ValueError, RuntimeError) as error:
            output['errors'].append({'index': job['index'], 'component': 'events', 'errorType': type(error).__name__})
        try:
            sid = job['parent_snapshot_id']
            need(isinstance(sid, str) and re.fullmatch('[0-9a-f-]{36}', sid), 'Unexpected original snapshot ID')
            data = rt.read(repository / 'catalog/records' / (sid + '.json'))
            need(hashlib.sha256(data).hexdigest() == job['catalog_sha256'], 'Original catalog record changed')
            record = json.loads(data)
            need(record['id'] == sid, 'Original record identity differs')
            resource = record['resources']
            need(all(type(resource.get(k)) is int and resource[k] > 0 for k in ('cpu_count', 'memory_mib')),
                 'Original resource metadata missing')
            value['resources'] = {k: resource[k] for k in ('cpu_count', 'memory_mib')}
        except (OSError, ValueError, RuntimeError) as error:
            output['errors'].append({'index': job['index'], 'component': 'resources', 'errorType': type(error).__name__})
        output['jobs'].append(value)
    output['complete'] = not output['errors'] and all(row['events'] is not None and row['resources'] is not None
                                                    for row in output['jobs'])
    return output


def apply_supplement(original, supplement):
    """Return a copied reference and normalized events; never rewrite raw input."""
    import copy
    need(supplement.get('revision') == 'original-reference-supplement-v1' and supplement.get('readOnly') is True,
         'Unrecognized original supplement')
    need(len(original.get('groups', [])) == 1, 'One original group required')
    group = original['groups'][0]
    need(supplement.get('runId') == group['run_id'] and supplement.get('sourceReportSha256') ==
         group['full_cache_evidence']['sha256'] and supplement.get('originalCoreCommit') == ORIGINAL,
         'Supplement is not bound to the returned original group')
    result = copy.deepcopy(original)
    rows = supplement.get('jobs', [])
    need(len(rows) == 8 and len({(r['instanceId'], r['slot']) for r in rows}) == 8, 'Supplement jobs differ')
    by_key = {(r['instanceId'], r['slot']): r for r in rows}
    events = []
    for job in result['groups'][0]['cache']['jobs']:
        value = by_key[job['instance_id'], job['slot']]
        need(value['sandboxId'] == job['sandbox_id'] and value['originalTemplateId'] == job['template_id'] and
             value['parentSnapshotId'] == job['parent_snapshot_id'] and value['replaySha256'] == job['replay_sha256'] and
             value['catalogSha256'] == job['catalog_sha256'], 'Supplement per-job identity differs')
        if value.get('resources') is not None:
            job['resources'] = copy.deepcopy(value['resources'])
        if value.get('events') is not None:
            events.append({'instanceId': value['instanceId'], 'slot': value['slot'], 'events': copy.deepcopy(value['events'])})
    return result, events
