"""Streaming per-template observations; never a cross-node physical net claim."""
import copy


def number(value):
    return type(value) is int and value >= 0


def phase_for(before, after):
    if before != after:
        return 'transition'
    states = list(after.values())
    if states == ['REPLAY_COMPLETED'] * 2:
        return 'after_replay'
    if states == ['REPLAYING'] * 2:
        return 'both_replaying'
    if states == ['READY'] * 2:
        return 'before_replay'
    if set(states) == {'REPLAYING', 'REPLAY_COMPLETED'}:
        return 'mixed_running_idle'
    return 'mixed_or_failed'


def stats_add(stats, value):
    if not number(value):
        stats['missing'] += 1
        return
    stats['count'] += 1
    stats['sum'] += value
    stats['min'] = value if stats['min'] is None else min(stats['min'], value)
    stats['max'] = value if stats['max'] is None else max(stats['max'], value)


def empty_stats():
    return {'count': 0, 'missing': 0, 'sum': 0, 'min': None, 'max': None}


class Metrics:
    def __init__(self):
        self.rows = {}
        self.guests = {}
        self.samples = 0
        self.host = {'runtimeCgroupBytes': empty_stats(), 'providerPssBytes': empty_stats(),
                     'providerCgroupBytes': empty_stats(), 'providerCoverageBytes': empty_stats()}

    def add(self, sample, jobs):
        self.samples += 1
        start = {r['sandboxId']: r['state'] for r in sample.get('jobStatesAtCollectionStart', [])}
        end = {r['sandboxId']: r['state'] for r in sample.get('jobStatesAtCollectionEnd', [])}
        ram = sample.get('ram', {})
        guests = {g['sandboxId']: g for g in ram.get('guests', [])} if ram.get('available') is True else {}
        for index in range(4):
            pair = sorted((j for j in jobs if j['templateIndex'] == index), key=lambda j: j['slot'])
            if len(pair) != 2:
                continue
            ids = [j['sandboxId'] for j in pair]
            phase = phase_for({sid: start.get(sid) for sid in ids}, {sid: end.get(sid) for sid in ids})
            key = (index, phase)
            row = self.rows.setdefault(key, {'templateIndex': index, 'phase': phase, 'samples': 0,
                'windowStartNs': sample['startNs'], 'windowEndNs': sample['endNs'],
                'metrics': {name: empty_stats() for name in ('wholeFcRssSumBytes', 'wholeFcPssSumBytes',
                    'conditionalWholeFcSharedBytes', 'actualGuestRamPssSumBytes', 'privateUpperResidentBytes')}})
            row['samples'] += 1
            row['windowStartNs'] = min(row['windowStartNs'], sample['startNs'])
            row['windowEndNs'] = max(row['windowEndNs'], sample['endNs'])
            selected = [guests.get(sid, {}) for sid in ids]
            for job, guest in zip(pair, selected):
                guest_key = (index, job['slot'], phase)
                detail = self.guests.setdefault(guest_key, {'templateIndex': index, 'slot': job['slot'],
                    'sandboxId': job['sandboxId'], 'phase': phase, 'metrics': {name: empty_stats() for name in
                    ('wholeFcRssBytes', 'wholeFcPssBytes', 'actualGuestRamPssBytes')}})
                whole = guest.get('wholeProcess', {})
                observations = {'wholeFcRssBytes': whole.get('rss_bytes') if whole.get('available') is True else None,
                                'wholeFcPssBytes': whole.get('pss_bytes') if whole.get('available') is True else None,
                                'actualGuestRamPssBytes': guest.get('guestRam', {}).get('bytes', {}).get('Pss')}
                for name, observation in observations.items():
                    stats_add(detail['metrics'][name], observation)
            def total(get):
                values = [get(g) for g in selected]
                return sum(values) if all(number(v) for v in values) else None
            rss = total(lambda g: g.get('wholeProcess', {}).get('rss_bytes')
                        if g.get('wholeProcess', {}).get('available') is True else None)
            pss = total(lambda g: g.get('wholeProcess', {}).get('pss_bytes')
                        if g.get('wholeProcess', {}).get('available') is True else None)
            actual = total(lambda g: g.get('guestRam', {}).get('bytes', {}).get('Pss'))
            upper = total(lambda g: g.get('rootfsUpper', {}).get('residentPageBytes')
                          if g.get('rootfsUpper', {}).get('available') is True
                          and ram.get('privateUpper', {}).get('available') is True else None)
            values = {'wholeFcRssSumBytes': rss, 'wholeFcPssSumBytes': pss,
                      'conditionalWholeFcSharedBytes': rss - pss if number(rss) and number(pss) and rss >= pss else None,
                      'actualGuestRamPssSumBytes': actual, 'privateUpperResidentBytes': upper}
            for name, value in values.items():
                stats_add(row['metrics'][name], value)
        runtime = sample.get('runtimeCharge', {})
        provider = sample.get('provider', {})
        process, cgroup = provider.get('wholeProcess', {}), provider.get('cgroup', {})
        values = {'runtimeCgroupBytes': runtime.get('currentBytes') if runtime.get('available') is True else None,
                  'providerPssBytes': process.get('pss_bytes') if provider.get('available') is True and process.get('available') is True else None,
                  'providerCgroupBytes': cgroup.get('currentBytes') if provider.get('available') is True and cgroup.get('available') is True else None,
                  'providerCoverageBytes': provider.get('sdkReportedBackingCoverageBytes') if provider.get('available') is True else None}
        for name, value in values.items():
            stats_add(self.host[name], value)

    def result(self):
        rows, host = copy.deepcopy(list(self.rows.values())), copy.deepcopy(self.host)
        guests = copy.deepcopy(list(self.guests.values()))
        for values in [host, *[r['metrics'] for r in rows], *[r['metrics'] for r in guests]]:
            for value in values.values():
                value['mean'] = value['sum'] / value['count'] if value['count'] else None
                del value['sum']
        return {'sampleCount': self.samples, 'templateRows': rows, 'guestRows': guests, 'hostObservations': host,
                'conditionalSharingFormula': 'sum(RSS-PSS)/(N-1), N=2 per template on one host',
                'externalSharersExcluded': False, 'memfileAttributionEstablished': False,
                'providerCoverageIsPhysicalCost': False, 'metricColumnsAreAdditive': False,
                'hostLowerAccessResidency': None, 'globalNetSavingBytes': None}
