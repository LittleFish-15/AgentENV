"""Matched two-node ordinary/lazy real-Guest comparison; physical net stays NA."""
import argparse
import hashlib
import json
from pathlib import Path


def need(ok, message):
    if not ok:
        raise ValueError(message)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def gate(pair, stage):
    key = stage + 'Gate'
    sample_key = stage + 'Sample'
    a, b = pair['node-a'][key], pair['node-b'][key]
    need({k:v for k,v in a.items() if k!='node'} == {k:v for k,v in b.items() if k!='node'}
         and a['status'] == 'COORDINATED_EIGHT_GUEST_GATE_COMPLETED'
         and a['node']=='node-a' and b['node']=='node-b', 'Two-node gate differs')
    for node, report in pair.items():
        ready, measured = a['readies'][node], a['measurements'][node]
        need(ready['node'] == node and ready['variant'] == stage and ready['epoch'] == a['epoch']
             and ready['runId'] == report['runId'] and len(ready['sandboxIds']) == 8
             and set(ready['sandboxIds']) == {j['sandboxId'] for j in report['jobs']}
             and measured['readySha256'] == digest(ready) and measured['sampleSha256'] == digest(report[sample_key]),
             'Gate does not bind actual Guests and sample')
    samples = [r[sample_key] for r in pair.values()]
    need(all(x.get('rootfsLowerFreshSample') and x['rootfsLowerFiles'].get('available') for x in samples),
         'Both nodes need fresh whole-lower residency samples')
    return {'epoch': a['epoch'], 'startNs': min(s['startNs'] for s in samples), 'endNs': max(s['endNs'] for s in samples),
            'atomicSnapshot': False, 'ordinaryLowerResidentBytes': sum(s['rootfsLowerFiles']['residentBytes'] for s in samples),
            'perNode': {node: report[sample_key] for node, report in pair.items()}}


def signature(report):
    templates = []
    for item in report['ordinaryTemplates']:
        evidence = item['snapshotEvidence']
        templates.append((item['templateIndex'], evidence['snapshotId'], evidence['committedRecordSha256'], digest(evidence['rootfsLayers'])))
    jobs = sorted((j['instanceId'], j['slot'], j['originalTemplateId'], j['replaySha256'],
                   j['resources']['cpu_count'], j['resources']['memory_mib'], j['stepsCompleted']) for j in report['jobs'])
    return sorted(templates), jobs, report['binaryPins']


def compare(reports):
    need(len(reports) == 4 and {(r['scenario'], r['node']) for r in reports} ==
         {(v, n) for v in ('off', 'lazy') for n in ('node-a', 'node-b')}, 'Need complete matched two-node rounds')
    reference = signature(reports[0])
    for report in reports:
        need(signature(report) == reference, 'Snapshots, binaries, workloads, resources or completion differ')
        jobs = report['jobs']
        need(len(jobs) == len({j['sandboxId'] for j in jobs}) == 8
             and all(j['state'] == 'REPLAY_COMPLETED' and j.get('privateUpperIsolationPassed') is True
                     and j['resources']['cpu_count'] == 2 and j['resources']['memory_mib'] == 4096 for j in jobs)
             and len({j['instanceId'] for j in jobs}) == 4, 'Incomplete real-Guest cohort')
        need(sum(j['stepsCompleted'] for j in jobs) == 382, 'Expected 382 actual actions per node')
        need(report['status'] == 'LAZY_FOUR_REPLAY_COMPLETED_OWNED_GUESTS_RELEASED' and report['workerExitCode'] == 0
             and report['ownedGuestsReleased'] is True and report['outcomeUncertain'] is False, 'Guest lifecycle is unresolved')
        need(report['preAdmissionLowerCacheAfter']['residentBytes'] == 0
             and report['preAdmissionLowerCacheAfter']['evictionRequested'] is True, 'Matching cold lower condition not established')
        for key in ('rootfsBindingEvidence', 'finalRootfsBindingEvidence'):
            need(report[key]['status'] == 'EIGHT_ACTUAL_GUEST_ROOTFS_BINDINGS_VERIFIED'
                 and report[key]['mode'] == report['scenario'] and len(report[key]['guests']) == 8,
                 'Ordinary/lazy binding acceptance missing')
    rounds = {}
    for variant in ('off', 'lazy'):
        pair = {r['node']: r for r in reports if r['scenario'] == variant}
        rounds[variant] = {stage: gate(pair, stage) for stage in ('admission', 'completed')}
    lazy_samples = rounds['lazy']['completed']['perNode']
    providers = {node: row['provider'] for node, row in lazy_samples.items()}
    need(all(p.get('available') and p.get('enabled') for p in providers.values()), 'Lazy provider observations missing')
    a, b = providers['node-a'], providers['node-b']
    need(a['cacheId'] == b['cacheId'] and a['pool'] == b['pool'], 'Nodes did not import the same pool object')
    # Broker read counters must be positive on BOTH nodes. Do not infer reads
    # merely from an SDK mapping or a healthy Runtime.
    need(all(p['counters'].get('nodeReadRequests', 0) > 0 and p['counters'].get('nodeReadBytes', 0) > 0
             for p in providers.values()), 'No actual lazy broker reads on a node')
    need(all(p['counters'].get('fillErrors') == 0 for p in providers.values()), 'Cache fill errors prevent full acceptance')
    coverage = a.get('sdkReportedBackingCoverageBytes')
    if type(coverage) is not int or coverage <= 0 or coverage != b.get('sdkReportedBackingCoverageBytes'):
        coverage = None
    rows = []
    for stage in ('admission', 'completed'):
        baseline = rounds['off'][stage]['ordinaryLowerResidentBytes']
        experimental = rounds['lazy'][stage]['ordinaryLowerResidentBytes']
        reduction = baseline - experimental
        rows.append({'stage': stage, 'baselineLocalLowerResidentBytes': baseline,
                     'lazyLocalLowerResidentBytes': experimental, 'localLowerCacheReductionBytes': reduction,
                     'localLowerCacheReductionFraction': reduction / baseline if baseline else None,
                     'oncePerObjectCoverageBudgetBytes': coverage,
                     'localReductionMinusCoverageModelBytes': reduction - coverage if coverage is not None else None,
                     'globalPhysicalNetSavingBytes': None})
    return {'status': 'TWO_NODE_REAL_GUEST_OFF_LAZY_COMPARISON', 'guestsPerRound': 16, 'actionsPerRound': 764,
            'sameSnapshotsAndBinaries': True, 'rootfsPath': 'ordinary_overlaybd_ublk_with_optional_lazy_UB_lower',
            'memfileCrossNodeCowImplemented': False, 'nativeDax': False, 'rows': rows,
            'pool': a['pool'], 'cacheId': a['cacheId'], 'rounds': rounds, 'reports': reports,
            'globalPhysicalNetSavingBytes': None, 'notes': [
                'Whole ordinary lower file residency is measured; it is not the per-Guest actual-access/residency intersection.',
                'Each round has sixteen Guests, identical snapshot IDs, binary hashes, private traces, CPU and RAM settings.',
                'Independent copies are hash-verified before measurement; scoped fadvise/mincore verifies zero lower residency before Guest admission in both rounds.',
                'Guest restored RAM/cache is identical snapshot content. Host metadata, decoding state and background load may still differ.',
                'The fixed pool is 256MiB; 64KiB chunks may read more than requested and can be evicted/reloaded. A fixed pool is not physical demand allocation.',
                'SDK backing coverage is counted once for the same object. The coverage subtraction is only a budget model, excludes additional overhead, and is not physical net savings.',
                'Provider RSS/PSS, node copy buffers, Guest caches, private uppers and Runtime cgroups overlap; their counters must not be blindly added.',
                'Input archives and retained independent source copies may occupy auxiliary host cache. They remain outside the lower-only metric and are visible only in broader host observations.',
                'The off round precedes lazy; non-atomic gate windows and different background load are retained in the report. No positive result is guaranteed.',
                'Old single-node eight-Guest measurements are historical background only and are not subtracted from these sixteen-Guest rounds.']}


def markdown(result):
    def mib(n):
        return 'NA' if n is None else f'{n / 1024**2:.3f}'
    lines = ['# 两节点真实沙箱：UB关闭 / 按需共享缓存', '',
             '每轮 A/B 各4模板×2沙箱，共16沙箱、764条动作；同快照、同二进制、每沙箱2vCPU/4GiB。', '',
             '本轮只验收普通块路径的rootfs按需缓存。memfile跨节点CoW未实现；物理净收益NA。', '',
             '| 同步检查点 | UB关闭：两节点lower驻留 MiB | 按需UB：两节点lower驻留 MiB | 本地lower缓存减少 MiB | 减去一次SDK覆盖的预算模型 MiB |',
             '|---|---:|---:|---:|---:|']
    for row in result['rows']:
        lines.append('| ' + ' | '.join([row['stage']] + [mib(row[k]) for k in
            ('baselineLocalLowerResidentBytes', 'lazyLocalLowerResidentBytes', 'localLowerCacheReductionBytes', 'localReductionMinusCoverageModelBytes')]) + ' |')
    lines += ['', '上述预算模型尚未扣齐辅助开销，也不证明SDK覆盖等于物理增量；不得称为实测净收益。', '',
              '| 轮次 | 节点 | 实际动作 | 非零命令 | 最早开始到最后完成 秒 | 实际采样帧 |', '|---|---|---:|---:|---:|---:|']
    for report in result['reports']:
        jobs = report['jobs']
        duration = max(j['replayFinishedUnix'] for j in jobs) - min(j['replayStartedUnix'] for j in jobs)
        lines.append('| ' + ' | '.join((report['scenario'], report['node'], str(sum(j['stepsCompleted'] for j in jobs)),
            str(sum(j['failedCommands'] for j in jobs)), f'{duration:.3f}', str(report['measurementSummary']['sampleCount']))) + ' |')
    lines += ['', '每沙箱RSS/PSS、实际Guest RAM VMA、upper、provider计数与Host曲线均保留在JSON及节点原始samples.jsonl；缺项保持NA。', '',
              '## 统计与适用边界', ''] + ['- ' + note for note in result['notes']]
    return '\n'.join(lines) + '\n'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--report', type=Path, action='append', required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    reports, pins = [], []
    for path in args.report:
        need(path.is_file() and not path.is_symlink() and path.stat().st_size <= 16 * 1024**2, 'Invalid report input')
        raw = path.read_bytes(); reports.append(json.loads(raw))
        pins.append({'name': path.name, 'sha256': hashlib.sha256(raw).hexdigest()})
    result = compare(reports); result['sourceFiles'] = pins
    args.output.mkdir(exist_ok=False, parents=True)
    (args.output / 'comparison.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    (args.output / 'comparison.md').write_text(markdown(result), encoding='utf-8')
    print(json.dumps({'status': result['status'], 'output': str(args.output)}))


if __name__ == '__main__':
    main()
