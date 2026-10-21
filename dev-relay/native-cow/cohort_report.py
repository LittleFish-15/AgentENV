"""Compare locally returned cohort reports without fabricating missing costs.

Accepts the four declared A/B original/native reports. It never reads private
benchmark input, connects to a node or publishes results.
"""
import argparse
import hashlib
import json
from pathlib import Path
import statistics


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def delta(original, native):
    if original is None or native is None:
        return {'original': original, 'native': native, 'reduction': None, 'reductionFraction': None}
    return {'original': original, 'native': native, 'reduction': original - native,
            'reductionFraction': (original - native) / original if original else None}


def average(values):
    return statistics.mean(values) if values and all(isinstance(x, (int, float)) and not isinstance(x, bool)
                                                   for x in values) else None


def after_sample(report):
    samples = [s for s in report.get('cohort', {}).get('samples', []) if s.get('phase') == 'after_workload']
    return samples[0] if len(samples) == 1 else {}


def guest_ram_pss(report):
    sample = after_sample(report).get('ram', {})
    guests = sample.get('guests', [])
    if sample.get('available') is not True or len(guests) != 2:
        return None
    numbers = [g.get('guestRam', {}).get('bytes', {}).get('Pss') for g in guests]
    return sum(numbers) if all(type(x) is int and x >= 0 for x in numbers) else None


def conditional_process_sharing(report):
    """Colleague's RSS/PSS estimator; explicitly whole FC, not memfile bytes."""
    sample = after_sample(report).get('ram', {})
    guests = sample.get('guests', [])
    if sample.get('available') is not True or len(guests) != 2:
        return {'status': 'NA', 'conditionalBytes': None}
    values = []
    for guest in guests:
        metric = guest.get('wholeProcess', {})
        if metric.get('available') is not True:
            return {'status': 'NA', 'conditionalBytes': None}
        rss, pss = metric.get('rss_bytes'), metric.get('pss_bytes')
        if type(rss) is not int or type(pss) is not int or rss < pss:
            return {'status': 'NA_NONATOMIC_OR_INVALID', 'conditionalBytes': None}
        values.append(rss - pss)
    return {'status': 'CONDITIONAL_WHOLE_FC_ESTIMATOR', 'conditionalBytes': sum(values),
            'formula': 'sum(RSS-PSS)/(N-1), N=2',
            'externalSharersExcluded': False, 'memfileAttributionEstablished': False}


def dax_evidence(report):
    missing = {'status': 'NA_FILE_DAX_OBSERVATION_INCOMPLETE', 'allReadFilesDax': None,
               'physicalSharedBytes': None, 'hostLowerAccessResidencyMeasured': False}
    rows = report.get('cohort', {}).get('workloads', [])
    if len(rows) != 2:
        return missing
    totals = dict.fromkeys(('files', 'daxFiles', 'nonDaxFiles', 'unknownFiles',
                           'daxReadPayloadBytes', 'nonDaxReadPayloadBytes', 'unknownReadPayloadBytes'), 0)
    for row in rows:
        value = row.get('result') or {}
        observed = value.get('fileDax', {})
        if row.get('passed') is not True or any(type(observed.get(k)) is not int or observed[k] < 0 for k in totals):
            return missing
        if (observed['files'] != value.get('fileCount') or observed['files'] <= 0
                or observed['daxFiles'] + observed['nonDaxFiles'] + observed['unknownFiles'] != observed['files']
                or observed['daxReadPayloadBytes'] + observed['nonDaxReadPayloadBytes'] + observed['unknownReadPayloadBytes'] != value.get('fileBytes')):
            return missing
        for key in totals:
            totals[key] += observed[key]
    complete = totals['unknownFiles'] == 0
    return {**totals, 'status': 'EFFECTIVE_DAX_ON_READ_FDS_OBSERVED' if complete else missing['status'],
            'allReadFilesDax': totals['nonDaxFiles'] == 0 if complete else None,
            'complete': complete, 'physicalSharedBytes': None, 'hostLowerAccessResidencyMeasured': False,
            'payloadBytesAreResidentOrDeduplicatedBytes': False,
            'scope': 'effective_DAX_queried_before_and_after_each_same_FD_read'}


def paired_window(by, variant):
    missing = {'status': 'NA_NO_COMPLETE_PAIRED_HOLD', 'atomicSnapshot': False,
               'synchronizedWorkloadStart': False}
    def digest(value):
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()
    try:
        pair = {node: by[node, variant]['cohort']['pairedWindow'] for node in ('node-a', 'node-b')}
        a, b = pair['node-a'], pair['node-b']
        if (any(value.get('status') != 'COORDINATED_POST_WORKLOAD_HOLD_COMPLETED' for value in pair.values())
                or a.get('epoch') != b.get('epoch') or not isinstance(a.get('epoch'), str) or len(a['epoch']) != 32
                or any(c not in '0123456789abcdef' for c in a['epoch'])
                or a.get('readies') != b.get('readies') or a.get('measurements') != b.get('measurements')
                or set(a['readies']) != {'node-a', 'node-b'} or set(a['measurements']) != {'node-a', 'node-b'}):
            return missing
        complete = True
        for node in ('node-a', 'node-b'):
            report = by[node, variant]
            ready, measured, sample = a['readies'][node], a['measurements'][node], after_sample(report)
            if (pair[node].get('node') != node or ready.get('node') != node or ready.get('variant') != variant
                    or ready.get('epoch') != a['epoch'] or ready.get('runId') != report['cohort'].get('runId')
                    or not isinstance(ready.get('sandboxIds'), list) or len(set(ready['sandboxIds'])) != 2
                    or len(ready['sandboxIds']) != 2 or measured.get('node') != node
                    or measured.get('epoch') != a['epoch'] or measured.get('readySha256') != digest(ready)
                    or not sample or measured.get('sampleSha256') != digest(sample)):
                return missing
            complete = complete and sample.get('ram', {}).get('available') is True
        return {'status': 'COORDINATED_POST_WORKLOAD_HOLD_COMPLETED', 'epoch': a['epoch'],
                'atomicSnapshot': False, 'synchronizedWorkloadStart': False,
                'guestRamObservationsAvailableOnBothNodes': complete,
                'scope': 'both_workers_waited_for_both_measurement_receipts_before_owned_cleanup'}
    except (KeyError, TypeError, ValueError):
        return missing


def compare(reports):
    need(len(reports) == 4, 'Exactly four reports required: A/B original and native')
    by = {(r.get('node'), r.get('variant')): r for r in reports}
    need(set(by) == {(n, v) for n in ('node-a', 'node-b') for v in ('original', 'native')},
         'Repeated or missing node/variant')
    for report in reports:
        need(report.get('sourceImage') and report.get('workloadSha256'), 'Missing input identity')
    inputs_match = len({r['sourceImage'] for r in reports}) == len({r['workloadSha256'] for r in reports}) == 1
    functional = all(r.get('status') == 'COHORT_FUNCTIONAL_PASS_SNAPSHOTS_RETAINED'
                     and r.get('cohort', {}).get('lifecyclePassed') is True
                     and r['cohort'].get('phase') == 'quiesced'
                     and r['cohort'].get('outcomeUncertain') is False
                     and r['cohort'].get('openRequests') == r['cohort'].get('sandboxIds') == []
                     and len(r['cohort'].get('workloads', [])) == 2 for r in reports)
    contents = set()
    for report in reports:
        for row in report.get('cohort', {}).get('workloads', []):
            value = row.get('result') or {}
            contents.add(tuple(value.get(k) for k in ('revision', 'catalogSha256', 'sqlSha256', 'queryCount', 'fileCount', 'fileBytes')))
            functional = functional and row.get('passed') is True and row.get('privateUpperIsolationPassed') is True
    workload_equal = inputs_match and len(contents) == 1 and None not in next(iter(contents), (None,))
    paired = functional and workload_equal
    nodes = {}
    for node in ('node-a', 'node-b'):
        original, native = by[node, 'original'], by[node, 'native']
        same_boot = original.get('bootId') == native.get('bootId') and bool(original.get('bootId'))
        compatible = paired and same_boot
        def mean_seconds(r):
            return average([(w.get('result') or {}).get('seconds') for w in r['cohort'].get('workloads', [])])
        def charge(r):
            value = after_sample(r).get('runtimeCharge', {})
            return value.get('currentBytes') if value.get('available') is True else None
        def upper(r):
            ram = after_sample(r).get('ram', {})
            if ram.get('available') is not True:
                return None
            value = ram.get('privateUpper', {})
            return value.get('residentPageBytes') if value.get('available') is True else None
        def guest_cache(r):
            return average([(w.get('result') or {}).get('guestMemoryBytes', {}).get('Cached')
                            for w in r['cohort'].get('workloads', [])])
        nodes[node] = {
            'sameBoot': same_boot, 'comparablePublicWorkload': compatible,
            'guestWorkloadMeanSeconds': delta(mean_seconds(original) if compatible else None,
                                              mean_seconds(native) if compatible else None),
            'actualGuestRamPssSumBytes': delta(guest_ram_pss(original) if compatible else None,
                                               guest_ram_pss(native) if compatible else None),
            'runtimeCgroupChargeBytes': delta(charge(original) if compatible else None,
                                               charge(native) if compatible else None),
            'privateUpperResidentBytes': delta(upper(original) if compatible else None,
                                                upper(native) if compatible else None),
            'guestReportedCachedMeanBytes': delta(guest_cache(original) if compatible else None,
                                                    guest_cache(native) if compatible else None),
            'guestCacheRootfsAttributionEstablished': False,
            'originalProviderObservation': after_sample(original).get('provider'),
            'nativeProviderObservation': after_sample(native).get('provider'),
            'originalFileDax': dax_evidence(original), 'nativeFileDax': dax_evidence(native),
            'runtimeChargeIsGlobalNetSaving': False,
            'originalConditionalProcessSharing': conditional_process_sharing(original),
            'nativeConditionalProcessSharing': conditional_process_sharing(native)}
    windows = {variant: paired_window(by, variant) for variant in ('original', 'native')}
    common_hold = all(w['status'] == 'COORDINATED_POST_WORKLOAD_HOLD_COMPLETED' for w in windows.values())
    return {'revision': 'cohort-comparison-v1',
            'status': 'PUBLIC_WORKLOAD_COMPARISON_WITH_EXPLICIT_GAPS' if paired else 'INCOMPLETE_COMPARISON_NO_BENEFIT_CLAIM',
            'matchedInputsAndGuestOutputs': workload_equal, 'allFourFunctionalCohortsPassed': functional,
            'nodes': nodes, 'pairedResidencyWindows': windows, 'globalNetSavingBytes': None, 'globalNetSavingFraction': None,
            'memfileCrossNodeCowAccepted': False,
            'rootfsCrossNodePhysicalSharingAcceptedByThisReport': False,
            'rootfsHostAccessResidency': None, 'UBPhysicalChargedBytes': None,
            'unresolved': [
                'Native Guest RAM private CoW is not implemented; local snapshot RAM CoW remains.',
                'Provider publication/import and matching content alone do not attest physical cross-node backing.',
                'This runner has no Host lower read observer; actual per-Guest access/residency intersections are NA.',
                'Effective DAX on actual read FDs describes the file access mode; cumulative read payload is not shared physical memory or a resident-page union.',
                'Provider RSS/PSS/cgroup and upper cache are separate observations; device-backed UB physical charge and full cost ownership remain incomplete, so global net is NA.',
                'Guest Cached is already within Guest RAM and must not be added again.',
                'Each variant has one two-Guest cohort; timing is descriptive, not a statistical performance result.',
                'Captures/Fork snapshots are retained; provider must stay alive until references are removed.',
                'Both nodes completed the coordinated post-workload hold; reads are non-atomic and workload starts were not synchronized.'
                if common_hold else 'No complete common two-node residency hold was established; do not claim simultaneous cross-node savings.']}


def markdown(result):
    lines = ['# Original / native public workload comparison', '', 'Status: `' + result['status'] + '`', '',
             '**Global net saving: NA. Native cross-node memfile private CoW: not implemented.**', '',
             '| Node | Metric | Original | Native | Reduction |', '|---|---|---:|---:|---:|']
    for node, values in result['nodes'].items():
        for name in ('guestWorkloadMeanSeconds', 'actualGuestRamPssSumBytes', 'runtimeCgroupChargeBytes',
                     'privateUpperResidentBytes', 'guestReportedCachedMeanBytes'):
            row = values[name]
            def show(value):
                return 'NA' if value is None else str(round(value, 6))
            lines.append('| ' + ' | '.join((node, name, show(row['original']), show(row['native']), show(row['reduction']))) + ' |')
    lines.extend(['', 'Runtime cgroup charge excludes the separately running UB provider. A positive difference here is not global net savings.', '',
                  '## Provider observations', '',
                  '| Node | Variant | RSS bytes | PSS bytes | Cgroup bytes | SDK coverage bytes (not physical cost) |',
                  '|---|---|---:|---:|---:|---:|'])
    for node, values in result['nodes'].items():
        for variant, key in (('original', 'originalProviderObservation'), ('native', 'nativeProviderObservation')):
            value = values.get(key) or {}
            process, group = value.get('wholeProcess', {}), value.get('cgroup', {})
            valid = value.get('available') is True
            fields = [process.get('rss_bytes') if valid and process.get('available') is True else None,
                      process.get('pss_bytes') if valid and process.get('available') is True else None,
                      group.get('currentBytes') if valid and group.get('available') is True else None,
                      value.get('sdkReportedBackingCoverageBytes') if valid else None]
            lines.append('| ' + ' | '.join([node, variant, *[show(v) for v in fields]]) + ' |')
    lines.extend(['', 'Device-backed UB memory can be uncharged here. Coverage values across two nodes are not additive physical allocations.', '',
                  '## Effective DAX on the workload read files', '',
                  '| Node | Variant | Files read | DAX files | Non-DAX files | Unknown files | Payload bytes read from DAX files |',
                  '|---|---|---:|---:|---:|---:|---:|'])
    for node, values in result['nodes'].items():
        for variant, key in (('original', 'originalFileDax'), ('native', 'nativeFileDax')):
            value = values[key]
            numbers = [value.get(k) for k in ('files', 'daxFiles', 'nonDaxFiles', 'unknownFiles', 'daxReadPayloadBytes')]
            lines.append('| ' + ' | '.join([node, variant, *[show(v) for v in numbers]]) + ' |')
    lines.extend(['', 'These are effective file modes observed on the actual read FDs. Payload counts can include repeated/aliased data; they are not physical or resident shared bytes.', '',
                  '## Two-node post-workload hold', ''])
    for variant, window in result['pairedResidencyWindows'].items():
        lines.append('- ' + variant + ': `' + window['status'] + '`' + ('; epoch `' + window['epoch'] + '`' if window.get('epoch') else ''))
    lines.extend(['', 'A completed hold establishes coordinated collection before either worker cleans its Guests. It is not an atomic physical-memory snapshot or a synchronized workload start.', '',
                  '## Measurement and implementation gaps', ''])
    lines.extend('- ' + text for text in result['unresolved'])
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    reports, sources = [], []
    for path in args.report:
        need(path.is_file() and not path.is_symlink() and path.stat().st_size <= 16 * 1024**2, 'Invalid report file')
        raw = path.read_bytes()
        reports.append(json.loads(raw))
        sources.append({'file': path.name, 'sha256': hashlib.sha256(raw).hexdigest()})
    result = compare(reports)
    result['sourceFiles'] = sources
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / 'comparison.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    (args.output / 'comparison.md').write_text(markdown(result), encoding='utf-8')
    print(json.dumps({'status': result['status'], 'reportDirectory': str(args.output)}))


if __name__ == '__main__':
    main()
