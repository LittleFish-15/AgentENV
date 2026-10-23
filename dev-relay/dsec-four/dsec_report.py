"""DSec measurements: exact replay gates and separate, non-additive ledgers.

No target actions. Reference observations are historical unless the caller has
independent contemporaneous experiment evidence. Missing fields remain null.
"""
import math


def numeric(value):
    return type(value) in (int, float) and math.isfinite(value)


def complete_sum(values):
    return sum(values) if values and all(numeric(v) for v in values) else None


def extrema(values):
    found = [v for v in values if numeric(v)]
    return {'validSamples': len(found), 'missingSamples': len(values) - len(found),
            'min': min(found) if found else None, 'max': max(found) if found else None,
            'mean': sum(found) / len(found) if found else None}


def normalize_job(row):
    def value(a, b):
        return row[a] if a in row else row.get(b)
    return {'instanceId': value('instanceId', 'instance_id'), 'slot': row.get('slot'),
            'replaySha256': value('replaySha256', 'replay_sha256'),
            'stepsCompleted': value('stepsCompleted', 'steps_completed'),
            'failedCommands': value('failedCommands', 'failed_commands'),
            'state': row.get('state'), 'sandboxId': value('sandboxId', 'sandbox_id'),
            'originalTemplateId': value('originalTemplateId', 'template_id'),
            'startedUnix': value('replayStartedUnix', 'replay_started_unix'),
            'finishedUnix': value('replayFinishedUnix', 'replay_finished_unix')}


def replay_comparison(candidate_jobs, reference_jobs, candidate_events=None, reference_events=None):
    """Events keyed by (instanceId, slot), with explicit step and Guest returnCode.

    Aggregate nonzero totals are diagnostic only. Equal hashes/counts do not
    substitute for per-command exit matching. Transport failure is never exit0.
    """
    rows = [normalize_job(row) for row in candidate_jobs]
    refs = [normalize_job(row) for row in reference_jobs]
    reasons = []
    key = lambda row: (row['instanceId'], row['slot'])
    current, reference = {key(r): r for r in rows}, {key(r): r for r in refs}
    if len(rows) != 8 or len(refs) != 8 or len(current) != 8 or len(reference) != 8:
        reasons.append('Eight unique template/slot pairs required in each cohort')
    identities_match = set(current) == set(reference) and len(current) == 8
    if not identities_match:
        reasons.append('Template/slot identities differ')
    paired = []
    for identity in sorted(set(current) & set(reference), key=str):
        new, old = current[identity], reference[identity]
        same = all(new[k] == old[k] and new[k] is not None
                   for k in ('replaySha256', 'originalTemplateId', 'stepsCompleted', 'failedCommands'))
        completed = new['state'] == old['state'] == 'REPLAY_COMPLETED'
        if not same or not completed:
            reasons.append('Replay identity/count/completion differs for ' + str(identity))
        exits_equal = None
        new_events = (candidate_events or {}).get(identity)
        old_events = (reference_events or {}).get(identity)
        if new_events is not None and old_events is not None:
            def sequence(events, count):
                if type(count) is not int or len(events) != count:
                    return None
                steps = [r.get('step') for r in events]
                codes = [r.get('returnCode') for r in events]
                if steps != list(range(count)) or not all(type(c) is int and 0 <= c <= 255 for c in codes):
                    return None
                if any(r.get('transportOk') is False or r.get('timedOut') is True for r in events):
                    return None
                if any(c in (124, 137) for c in codes):
                    return None
                return codes
            seq_new = sequence(new_events, new['stepsCompleted'])
            seq_old = sequence(old_events, old['stepsCompleted'])
            exits_equal = seq_new is not None and seq_old is not None and seq_new == seq_old
        if exits_equal is not True:
            reasons.append(('Missing exact command outcomes for ' if exits_equal is None else
                            'Command outcomes invalid/different for ') + str(identity))
        paired.append({'instanceId': identity[0], 'slot': identity[1],
                       'identityCountsMatch': same, 'bothCompleted': completed,
                       'exactCommandExitsMatch': exits_equal,
                       'candidateSeconds': new['finishedUnix'] - new['startedUnix']
                        if numeric(new['finishedUnix']) and numeric(new['startedUnix']) else None,
                       'referenceSeconds': old['finishedUnix'] - old['startedUnix']
                        if numeric(old['finishedUnix']) and numeric(old['startedUnix']) else None})
    return {'identitiesMatch': identities_match, 'sameReplayOutcomesAccepted': not reasons,
            'historicalReferenceOnly': True, 'sameCacheInitialStateEstablished': False,
            'causalPerformanceGainEstablished': False, 'reasons': reasons, 'pairs': paired}


def sample_totals(sample, expected_ids):
    guests = sample.get('ram', {}).get('guests', [])
    by_id = {row.get('sandboxId'): row for row in guests}
    duplicate = len(by_id) != len(guests)
    complete = not duplicate and len(expected_ids) == len(set(expected_ids)) and set(by_id) == set(expected_ids)
    selected = [by_id.get(sid, {}) for sid in expected_ids] if complete else [{} for _ in expected_ids]
    def total(get):
        return complete_sum([get(row) for row in selected])
    fc = total(lambda row: row.get('wholeProcess', {}).get('pss_bytes'))
    ram = total(lambda row: row.get('guestRam', {}).get('bytes', {}).get('Pss')
                if row.get('guestRam', {}).get('available') is True else None)
    pmem = total(lambda row: row.get('pmem', {}).get('bytes', {}).get('Pss')
                 if row.get('pmem', {}).get('available') is True else None)
    return {'startNs': sample.get('startNs'), 'endNs': sample.get('endNs'), 'completeGuestInventory': complete,
            'wholeFcPssSumBytes': fc, 'actualGuestRamPssSumBytes': ram,
            'pmemMappingPssSumBytes': pmem,
            'wholeFcRssSumBytesNonunique': total(lambda row: row.get('wholeProcess', {}).get('rss_bytes')),
            'fcPssAnonSumBytes': total(lambda row: row.get('wholeProcess', {}).get('rollupBytes', {}).get('Pss_Anon')),
            'fcPssFileSumBytes': total(lambda row: row.get('wholeProcess', {}).get('rollupBytes', {}).get('Pss_File')),
            # Both are sequential reads, so a negative residual is retained and
            # labelled; it is never clamped into invented savings/overhead.
            'fcOutsideGuestRamPssDifferenceBytes': fc - ram if numeric(fc) and numeric(ram) else None,
            'pmemIncludedInWholeFcPss': True, 'pmemOverlapsHostFileCache': True,
            'wholeHostCachedBytes': sample.get('host', {}).get('memoryBytes', {}).get('Cached'),
            'wholeHostBuffersBytes': sample.get('host', {}).get('memoryBytes', {}).get('Buffers'),
            'immutablePmemFileResidentBytes': sample.get('hostPmemFiles', {}).get('residentPageBytes'),
            'privateUpperResidentBytes': sample.get('ram', {}).get('privateUpper', {}).get('residentPageBytes'),
            'runtimeCgroupChargeBytes': sample.get('runtimeCharge', {}).get('currentBytes'),
            'providerPssBytes': sample.get('provider', {}).get('wholeProcess', {}).get('pss_bytes'),
            'collectorPssBytes': sample.get('collector', {}).get('pss_bytes'),
            'ownerControllerPssBytes': sample.get('ownerController', {}).get('pss_bytes'),
            'memoryLowerFileResidentBytes': sample.get('memoryLowerFiles', {}).get('residentPageBytes'),
            'liveMemoryDeviceResidentBytes': sample.get('memoryDevices', {}).get('uniqueResidentPageBytes'),
            'runtimeAndUblkPssSumBytes': complete_sum([r.get('wholeProcess', {}).get('pss_bytes')
                for r in sample.get('runtimeServices', {}).get('processes', [])])
                if sample.get('runtimeServices', {}).get('available') is True else None,
            'globalPhysicalSavingBytes': None, 'accessResidentIntersectionBytes': None}


def summarize(samples, jobs):
    ids = [normalize_job(row)['sandboxId'] for row in jobs]
    rows = [sample_totals(sample, ids) for sample in samples]
    fields = ('wholeFcPssSumBytes', 'actualGuestRamPssSumBytes', 'pmemMappingPssSumBytes',
              'wholeFcRssSumBytesNonunique', 'fcPssAnonSumBytes', 'fcPssFileSumBytes',
              'fcOutsideGuestRamPssDifferenceBytes', 'wholeHostCachedBytes', 'wholeHostBuffersBytes',
              'immutablePmemFileResidentBytes', 'privateUpperResidentBytes', 'runtimeCgroupChargeBytes',
              'providerPssBytes', 'collectorPssBytes', 'ownerControllerPssBytes', 'memoryLowerFileResidentBytes',
              'liveMemoryDeviceResidentBytes', 'runtimeAndUblkPssSumBytes')
    per_guest = []
    for job in map(normalize_job, jobs):
        selected = []
        for sample in samples:
            matches = [r for r in sample.get('ram', {}).get('guests', []) if r.get('sandboxId') == job['sandboxId']]
            selected.append(matches[0] if len(matches) == 1 else {})
        per_guest.append({'sandboxId': job['sandboxId'], 'instanceId': job['instanceId'], 'slot': job['slot'],
            'wholeFcRssBytes': extrema([r.get('wholeProcess', {}).get('rss_bytes') for r in selected]),
            'wholeFcPssBytes': extrema([r.get('wholeProcess', {}).get('pss_bytes') for r in selected]),
            'actualGuestRamPssBytes': extrema([r.get('guestRam', {}).get('bytes', {}).get('Pss') for r in selected])})
    per_template = []
    instances = sorted({normalize_job(j)['instanceId'] for j in jobs}, key=str)
    for instance in instances:
        pair = [normalize_job(j)['sandboxId'] for j in jobs if normalize_job(j)['instanceId'] == instance]
        pair_totals = []
        if len(pair) == 2:
            for sample in samples:
                subset = dict(sample, ram=dict(sample.get('ram', {}), guests=[r for r in
                    sample.get('ram', {}).get('guests', []) if r.get('sandboxId') in pair]))
                pair_totals.append(sample_totals(subset, pair))
        per_template.append({'instanceId': instance, 'sandboxIds': pair,
            'wholeFcPssSumBytes': extrema([r['wholeFcPssSumBytes'] for r in pair_totals]),
            'actualGuestRamPssSumBytes': extrema([r['actualGuestRamPssSumBytes'] for r in pair_totals])})
    return {'sampleCount': len(samples), 'sameCycleTotals': rows, 'perGuest': per_guest, 'perTemplate': per_template,
            'ranges': {field: extrema([row[field] for row in rows]) for field in fields},
            'columnsAreAdditive': False, 'maximaWereNotSummedAcrossTimes': True,
            'physicalNetSavingBytes': None, 'memfileCrossNodePrivateCowAccepted': False,
            'rootfsCrossNodePhysicalSharingAccepted': False,
            'actualRootfsAccessSetsCollected': False,
            'experimentUBAllocations': 0, 'wholeMachineUBPoolPhysicalBytes': None,
            'scope': 'ordinary_Host_file_pmem_DAX_each_Host_has_independent_pagecache'}


def markdown(report):
    summary = report['measurementSummary']
    comparison = report.get('replayComparison', {})
    lines = ['# DSec真实模板测量报告', '',
             '这是普通Host文件经virtio-pmem与Guest DAX的测量。两个Host仍各有自己的文件pagecache；'
             '本轮不构成memfile跨节点私有CoW或rootfs跨节点物理共享验收。', '',
             '**状态：** ' + str(report.get('status', 'NA')), '',
             '**完整逐命令对照通过：** ' + str(comparison.get('sameReplayOutcomesAccepted', False)), '',
             '原版是历史参考；缓存初态、后台活动和初始化路径未证明相同。'
             '未匹配逐命令退出码时，不给完整同负载收益结论。', '',
             '| 指标 | 最小值 MiB | 最大值 MiB | 有效 / 缺失样本 |',
             '|---|---:|---:|---:|']
    for key, row in summary['ranges'].items():
        def show(value): return f'{value / 1024**2:.3f}' if numeric(value) else 'NA'
        lines.append(f"| {key} | {show(row['min'])} | {show(row['max'])} | {row['validSamples']} / {row['missingSamples']} |")
    lines += ['', '全FC PSS、Guest RAM PSS和pmem映射PSS是包含关系；pmem映射又与Host文件cache重叠。'
              '上表各列不能相加。表中总峰先在同一采样周期求和，再取峰值，不相加各沙箱独立峰值。', '',
              '整文件驻留不是实际访问集合；本轮实际访问与同时窗驻留交并、全局物理净节省为NA。'
              '准备阶段全文件校验可能预热基底，需同时查看启动前绝对驻留和回放增量。', '',
              '## 各沙箱整进程PSS', '', '| 模板 / slot / Sandbox ID | 最小 MiB | 最大 MiB | 有效 / 缺失 |',
              '|---|---:|---:|---:|']
    for row in summary['perGuest']:
        value = row['wholeFcPssBytes']
        lo = f"{value['min']/1024**2:.3f}" if numeric(value['min']) else 'NA'
        hi = f"{value['max']/1024**2:.3f}" if numeric(value['max']) else 'NA'
        lines.append(f"| {row['instanceId']} / {row['slot']} / {row['sandboxId']} | {lo} | {hi} | {value['validSamples']} / {value['missingSamples']} |")
    lines += ['', '## 对照缺项', '']
    lines += ['- ' + reason for reason in comparison.get('reasons', [])] or ['- 无逐命令对照缺项；仍保留历史参考与计量边界。']
    return '\n'.join(lines) + '\n'
