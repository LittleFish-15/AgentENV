"""Compare returned private DSec measurements with an original memory recheck.

Local files only. Does not run an experiment or upload any input. Exact command
outcomes may be supplied separately; aggregate counts never substitute for them.
"""
import argparse, hashlib, importlib.util, json, math
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('dsec_report', HERE / 'dsec_report.py')
metrics = importlib.util.module_from_spec(spec);spec.loader.exec_module(metrics)


def need(ok, message):
    if not ok:
        raise ValueError(message)


def read_json(path, maximum=512 * 1024**2):
    path = Path(path)
    need(path.is_file() and not path.is_symlink() and path.stat().st_size <= maximum, 'Unexpected local input')
    raw = path.read_bytes()
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def events(rows):
    result = {}
    for row in rows or []:
        key = row['instanceId'], row['slot']
        need(key not in result and isinstance(row.get('events'), list), 'Repeated or missing command events')
        result[key] = row['events']
    return result


def bounds(jobs):
    normalized = [metrics.normalize_job(row) for row in jobs]
    starts, ends = [r['startedUnix'] for r in normalized], [r['finishedUnix'] for r in normalized]
    if not starts or not all(metrics.numeric(v) for v in starts + ends):
        return None
    need(all(a <= b for a, b in zip(starts, ends)), 'Negative replay duration')
    return min(starts), max(ends)


def original_view(group):
    cache, memory = group['cache'], group['memory']
    jobs = cache['jobs']
    window = bounds(jobs)
    cycles = memory['all_fc_same_cycle']
    usable = [r for r in cycles if r.get('valid') is True and
              metrics.numeric(r.get('sum_fc_pss_bytes')) and metrics.numeric(r.get('started_unix')) and
              metrics.numeric(r.get('finished_unix'))]
    inside = [r for r in usable if window and r['started_unix'] >= window[0] and r['finished_unix'] <= window[1]]
    end = usable[-1] if usable else {}
    files = cache['cache_timeseries']['file_rows']
    last = files[-1] if files else {}
    return {'runId': group['run_id'], 'jobs': jobs, 'replayWindowUnix': window,
            'fullReplaySeconds': window[1] - window[0] if window else None,
            'wholeFcPssSumDuringReplay': metrics.extrema([r['sum_fc_pss_bytes'] for r in inside]),
            'lastWholeFcPssSumBytes': end.get('sum_fc_pss_bytes'),
            'lastFcWindowUnix': [end.get('started_unix'), end.get('finished_unix')],
            'lastHostCachedDeltaBytes': last.get('host_cached_delta_after_bytes'),
            'lastRootfsLowerResidentBytes': last.get('lower_resident_bytes'),
            'lastMemoryLowerResidentBytes': last.get('memory_lower_resident_bytes'),
            'lastUpperResidentBytes': last.get('rootfs_upper_resident_bytes'),
            'lastAccessedResidentUnionBytes': last.get('accessed_resident_union_bytes'),
            'lastSameTemplateSharedResidentBytes': last.get('same_template_shared_resident_union_bytes'),
            'originalImplementation': cache['experiment_comparison'],
            'measurementCoverage': memory.get('coverage'),
            'fileAndProcessLastObservationsAreDifferentWindows': True}


def candidate_view(candidate):
    jobs = candidate['jobs']
    window = bounds(jobs)
    samples = candidate.get('rawObservations', [])
    inside = [s for s in samples if window and metrics.numeric(s.get('startNs')) and metrics.numeric(s.get('endNs'))
              and s['startNs'] / 1e9 >= window[0] and s['endNs'] / 1e9 <= window[1]]
    current = metrics.summarize(inside, jobs)
    before = [s for s in samples if s.get('phase') == 'before_replay' and s.get('heavySample') is True]
    after = [s for s in samples if s.get('phase') == 'after_replay' and s.get('heavySample') is True]
    ids = [metrics.normalize_job(j)['sandboxId'] for j in jobs]
    baseline = metrics.sample_totals(before[0], ids) if before else {}
    end = metrics.sample_totals(after[-1], ids) if after else {}
    start_cache, end_cache = baseline.get('wholeHostCachedBytes'), end.get('wholeHostCachedBytes')
    return {'runId': candidate['runId'], 'replayWindowUnix': window,
            'fullReplaySeconds': window[1] - window[0] if window else None,
            'wholeFcPssSumDuringReplay': current['ranges']['wholeFcPssSumBytes'],
            'lastWholeFcPssSumBytes': end.get('wholeFcPssSumBytes'),
            'lastActualGuestRamPssSumBytes': end.get('actualGuestRamPssSumBytes'),
            'lastPmemMappingPssSumBytes': end.get('pmemMappingPssSumBytes'),
            'lastHostCachedDeltaBytes': end_cache-start_cache
                if metrics.numeric(start_cache) and metrics.numeric(end_cache) else None,
            'lastImmutablePmemFileResidentBytes': end.get('immutablePmemFileResidentBytes'),
            'beforeReplayImmutablePmemFileResidentBytes': baseline.get('immutablePmemFileResidentBytes'),
            'lastUpperResidentBytes': end.get('privateUpperResidentBytes'),
            'lastRootfsActualAccessResidentUnionBytes': None,
            'lastFcWindowUnix': [end.get('startNs', 0)/1e9, end.get('endNs', 0)/1e9] if end else None,
            'perGuest': current['perGuest'], 'perTemplate': current['perTemplate'],
            'beforeReplay': baseline, 'afterReplay': end}


def compare(candidate, original, original_events=None):
    need(candidate.get('revision') == 'dsec-four-report-v1', 'Unsupported candidate report')
    need(original.get('groups') and len(original['groups']) == 1, 'Select one original group explicitly')
    group = original['groups'][0]
    need(group['cache']['experiment_comparison'].get('io64_core_changes_used') is False,
         'Expected true original implementation, not UB-off or modified IO64')
    old, new = original_view(group), candidate_view(candidate)
    matching = metrics.replay_comparison(candidate['jobs'], old['jobs'],
        events(candidate.get('commandOutcomes')), events(original_events))
    failures = []
    def resources(rows):
        result = {}
        for row in rows:
            normalized = metrics.normalize_job(row)
            resource = row.get('resources')
            if not isinstance(resource, dict) or any(type(resource.get(k)) is not int
                                                     for k in ('cpu_count', 'memory_mib')):
                return None
            result[normalized['instanceId'], normalized['slot']] = {
                key: resource[key] for key in ('cpu_count', 'memory_mib')}
        return result
    new_resources, old_resources = resources(candidate['jobs']), resources(old['jobs'])
    resource_match = new_resources is not None and old_resources is not None and new_resources == old_resources
    if not resource_match:
        failures.append('CPU/RAM resource evidence is missing or differs in the supplied reports')
    if candidate.get('ownedGuestsReleased') is not True:
        failures.append('Candidate Guest cleanup is not confirmed')
    if candidate.get('status') != 'NATIVE_FOUR_REPLAY_COMPLETED_OWNED_GUESTS_RELEASED':
        failures.append('Candidate replay is not complete')
    if candidate.get('observer', {}).get('status') != 'READONLY_OBSERVER_OWNER_FINISHED':
        failures.append('Candidate observer did not finish normally')
    validation = group['cache'].get('validation', {})
    if validation.get('all_cohort_guests_released') is not True or validation.get('replay_completed_guests') != 8:
        failures.append('Original replay/cleanup is not confirmed')
    comparisons = []
    for label, a, b in (
        ('Replay-window whole-FC PSS observed peak', old['wholeFcPssSumDuringReplay']['max'], new['wholeFcPssSumDuringReplay']['max']),
        ('Last observed whole-FC PSS sum', old['lastWholeFcPssSumBytes'], new['lastWholeFcPssSumBytes']),
        ('Host Cached replay delta', old['lastHostCachedDeltaBytes'], new['lastHostCachedDeltaBytes']),
        ('Private upper file residency', old['lastUpperResidentBytes'], new['lastUpperResidentBytes'])):
        delta = b-a if metrics.numeric(a) and metrics.numeric(b) else None
        comparisons.append({'metric': label, 'originalBytes': a, 'candidateBytes': b,
                            'candidateMinusOriginalBytes': delta,
                            'descriptiveDeltaPercent': delta/a*100 if metrics.numeric(delta) and a != 0 else None,
                            'causalSavingsAccepted': False})
    return {'revision': 'dsec-original-historical-comparison-v1', 'original': old, 'candidate': new,
            'replayComparison': matching, 'lifecycleGaps': failures, 'observationalDeltas': comparisons,
            'fullSameWorkloadComparisonAccepted': not failures and matching['sameReplayOutcomesAccepted'],
            'resourceEvidenceMatched': resource_match,
            'historicalReferenceOnly': True, 'globalPhysicalSavingBytes': None,
            'completeMemfileCrossNodeCoWAccepted': False, 'rootfsCrossNodePhysicalSharingAccepted': False,
            'cacheInitialStatesMatched': False,
            'initializationDifference': 'original retained templates versus freshly captured DSec clean parents',
            'hostRootfsRepresentationDifference': 'OverlayBD lower files versus per-template raw PMEM filesystem files',
            'columnsMustNotBeSummed': True}


def markdown(result):
    def mib(value): return f'{value/1024**2:.3f}' if metrics.numeric(value) else 'NA'
    lines = ['# DSec新版与原版历史对照', '',
        '**完整同负载验收：** ' + str(result['fullSameWorkloadComparisonAccepted']), '',
        '这是不同时间的历史对照。表中“新版减原版”是观测差值，负值不自动证明优化导致节省。'
        '全FC PSS与Host文件缓存重叠，不能相加为总物理内存。', '',
        '| 指标 | 原版 MiB | 新版 MiB | 新版减原版 MiB |', '|---|---:|---:|---:|']
    for row in result['observationalDeltas']:
        lines.append(f"| {row['metric']} | {mib(row['originalBytes'])} | {mib(row['candidateBytes'])} | {mib(row['candidateMinusOriginalBytes'])} |")
    lines += ['', '新版全FC PSS包含pmem文件映射；实际Guest RAM PSS另列。'
              '原版OverlayBD lower与新版raw文件不是同一种存储表示，不能把两者整文件驻留差直接叫消除重复缓存。', '',
              '- 新版回放前raw驻留：' + mib(result['candidate']['beforeReplayImmutablePmemFileResidentBytes']) + ' MiB',
              '- 新版回放后raw驻留：' + mib(result['candidate']['lastImmutablePmemFileResidentBytes']) + ' MiB',
              '- 新版末次Guest RAM ΣPSS：' + mib(result['candidate']['lastActualGuestRamPssSumBytes']) + ' MiB',
              '- 新版末次PMEM映射ΣPSS：' + mib(result['candidate']['lastPmemMappingPssSumBytes']) + ' MiB', '',
              '## 未满足的比较门槛', '']
    gaps = result['lifecycleGaps'] + result['replayComparison']['reasons']
    lines += ['- ' + reason for reason in gaps] or ['- 逐命令与生命周期门槛通过；历史时窗/缓存初态/计量边界仍然存在。']
    lines += ['', '完整memfile跨节点私有CoW、rootfs跨Host物理共享和全局物理净收益均未验收。'
              '普通Host文件DSec的功能收益需要与上述限定一起报告。']
    return '\n'.join(lines)+'\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', required=True)
    parser.add_argument('--original', required=True)
    parser.add_argument('--original-sha256', required=True)
    parser.add_argument('--original-events')
    parser.add_argument('--output-directory', required=True)
    args = parser.parse_args()
    candidate, candidate_sha = read_json(args.candidate)
    original, original_sha = read_json(args.original)
    need(original_sha == args.original_sha256, 'Original input hash differs')
    old_events = read_json(args.original_events, 32*1024**2)[0] if args.original_events else None
    result = compare(candidate, original, old_events)
    result.update(candidateInputSha256=candidate_sha, originalInputSha256=original_sha)
    target = Path(args.output_directory).absolute()
    need(not target.exists(), 'Existing analysis output preserved')
    target.mkdir(mode=0o777)
    (target/'comparison.json').write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding='utf-8')
    (target/'comparison.md').write_text(markdown(result), encoding='utf-8')
    print(json.dumps({'status': 'LOCAL_HISTORICAL_COMPARISON_WRITTEN', 'output': str(target),
                      'fullSameWorkloadComparisonAccepted': result['fullSameWorkloadComparisonAccepted'],
                      'globalPhysicalSavingBytes': None}))


if __name__ == '__main__': main()
