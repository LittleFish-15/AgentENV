"""CoW range accounting. Inputs are observations, never inferred from file size.

Intervals are half-open page-number ranges. PFNs may be compared only within
one host. Content overlap across hosts is reported as potential duplication,
not as proof of physical sharing or net memory savings.
"""
from collections import defaultdict


def uint(value, name='integer'):
    if type(value) is not int or not 0 <= value < 2**63:
        raise ValueError('Invalid ' + name)
    return value


def page_size(value):
    uint(value, 'page size')
    if not 4096 <= value <= 2**21 or value & (value - 1):
        raise ValueError('Page size must be a supported power of two')
    return value


def merge(ranges, limit=None):
    prepared = []
    for pair in ranges:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise ValueError('Expected half-open interval')
        start, end = (uint(x, 'page offset') for x in pair)
        if start >= end or (limit is not None and end > limit):
            raise ValueError('Empty, reversed or out-of-bounds interval')
        prepared.append((start, end))
    result = []
    for start, end in sorted(prepared):
        if result and start <= result[-1][1]:
            result[-1][1] = max(end, result[-1][1])
        else:
            result.append([start, end])
    return result


def intersect(left, right):
    left, right = merge(left), merge(right)
    result = []
    i = j = 0
    while i < len(left) and j < len(right):
        start, end = max(left[i][0], right[j][0]), min(left[i][1], right[j][1])
        if start < end:
            result.append([start, end])
        if left[i][1] <= right[j][1]:
            i += 1
        else:
            j += 1
    return result


def count(ranges):
    return sum(end - start for start, end in merge(ranges))


def sharing(readers, bytes_per_page):
    """Unique pool, shared unique pages, participation and duplicate avoidance.

    Deduplicates repeated accesses within each reader before counting readers.
    For N>2, shared_unique and avoided_duplicate are intentionally different.
    """
    bytes_per_page = page_size(bytes_per_page)
    if not readers:
        raise ValueError('At least one explicitly observed reader required')
    events = defaultdict(int)
    total = 0
    for ranges in readers:
        for start, end in merge(ranges):
            events[start] += 1
            events[end] -= 1
            total += end - start
    previous = None
    active = union = shared = participation = 0
    for position, delta in sorted(events.items()):
        if previous is not None:
            length = position - previous
            if active:
                union += length
            if active >= 2:
                shared += length
                participation += active * length
        active += delta
        if active < 0:
            raise ValueError('Invalid interval event balance')
        previous = position
    if active != 0:
        raise ValueError('Unclosed interval events')
    return {
        'unique_bytes': union * bytes_per_page,
        'shared_unique_bytes': shared * bytes_per_page,
        'shared_participation_bytes': participation * bytes_per_page,
        'avoided_duplicate_bytes': (total - union) * bytes_per_page,
        'total_reader_bytes': total * bytes_per_page,
        'shared_pool_fraction': shared / union if union else None,
        'duplicate_avoidance_fraction': (total - union) / total if total else None,
        'shared_participation_fraction': participation / total if total else None,
    }


def host_lower_access_residency(files, readers, bytes_per_page, trace):
    """Combine actual buffered read sets with contemporaneous cache residency.

    files: {file_id: {bytes, resident_pages}}, file_id is a *physical file*
    identity such as device/inode, not a content hash. All per-reader accesses
    refer to those same identities. Caller must bind these to scoped instances.
    No missing trace/residency data are converted to zero.
    """
    bytes_per_page = page_size(bytes_per_page)
    required = ('complete', 'instances_bound', 'same_window', 'no_content_reads_for_sampling', 'physical_file_ids_deduplicated')
    if not isinstance(trace, dict) or any(trace.get(k) is not True for k in required):
        return {'status': 'NA_INCOMPLETE_OBSERVATION', 'measurement': None}
    for field in ('dropped_records', 'unknown_sources', 'attribution_fallbacks'):
        if field not in trace or uint(trace[field], field) != 0:
            return {'status': 'NA_INCOMPLETE_OBSERVATION', 'measurement': None}
    if not isinstance(readers, dict) or not readers:
        raise ValueError('Explicit reader identities required')
    if not files and any(readers.values()):
        raise ValueError('Accesses have no bound file identities')
    resident = {}
    for key, info in files.items():
        length = uint(info['bytes'], 'file bytes')
        if length == 0 or info.get('resident_pages') is None:
            return {'status': 'NA_RESIDENCY_UNAVAILABLE', 'measurement': None}
        resident[key] = merge(info['resident_pages'], (length + bytes_per_page - 1) // bytes_per_page)
    bound = {}
    for reader, accesses in readers.items():
        if not isinstance(reader, str) or not reader or not isinstance(accesses, dict):
            raise ValueError('Invalid reader identity or access set')
        if not set(accesses) <= set(files):
            raise ValueError('Unbound file in reader accesses')
        bound[reader] = {}
        for key, ranges in accesses.items():
            limit = (files[key]['bytes'] + bytes_per_page - 1) // bytes_per_page
            bound[reader][key] = intersect(merge(ranges, limit), resident[key])
    fields = ('unique_bytes', 'shared_unique_bytes', 'shared_participation_bytes',
              'avoided_duplicate_bytes', 'total_reader_bytes')
    totals = dict.fromkeys(fields, 0)
    for key in files:
        row = sharing([items.get(key, []) for items in bound.values()], bytes_per_page)
        for name in fields:
            totals[name] += row[name]
    totals['shared_pool_fraction'] = totals['shared_unique_bytes'] / totals['unique_bytes'] if totals['unique_bytes'] else None
    totals['duplicate_avoidance_fraction'] = totals['avoided_duplicate_bytes'] / totals['total_reader_bytes'] if totals['total_reader_bytes'] else None
    totals['shared_participation_fraction'] = totals['shared_participation_bytes'] / totals['total_reader_bytes'] if totals['total_reader_bytes'] else None
    return {'status': 'BUFFERED_ACCESS_RESIDENCY_ACCOUNTED', 'measurement': totals,
            'per_reader_resident_bytes': {name: sum(count(v) for v in by_file.values()) * bytes_per_page
                                          for name, by_file in bound.items()},
            'zero_observed_buffered_reads': not any(count(r) for values in readers.values() for r in values.values()),
            'scope': 'actual buffered lower accesses intersected with observed residency; not all Guest file accesses',
            'physical_cross_node_sharing_accepted': False}


def same_node_ram_pfns(node, readers, bytes_per_page, evidence):
    """Account PFN sets only after explicit RAM-VMA binding and PFN visibility.

    Each reader is {node, pfns:[[first,last_exclusive],...]}. HugeTLB, KSM,
    global zero-page sharing and aliases require classification by the collector;
    absent classification means NA rather than silently crediting them to CoW.
    """
    page_size(bytes_per_page)
    for key in ('ram_vmas_bound', 'pfn_visible', 'same_sampling_epoch', 'special_pages_classified',
                'aliases_deduplicated', 'external_sharers_accounted', 'resident_pages_complete'):
        if evidence.get(key) is not True:
            return {'status': 'NA_RAM_PFN_EVIDENCE_INCOMPLETE', 'measurement': None}
    if not isinstance(node, str) or not node or not readers:
        raise ValueError('Explicit host and readers required')
    sets = []
    for reader in readers:
        if reader.get('node') != node:
            raise ValueError('PFNs from different hosts must never be compared')
        ranges = merge(reader['pfns'])
        if any(start == 0 for start, _ in ranges):
            raise ValueError('Zero/masked PFN cannot prove sharing')
        sets.append(ranges)
    return {'status': 'SAME_NODE_RAM_PFN_UNION_ACCOUNTED', 'node': node,
            'measurement': sharing(sets, bytes_per_page),
            'cross_node_physical_base_proven': False, 'memfile_cow_cause_proven': False,
            'scope': 'provided classified RAM PFN sets; sharing cause is not inferred'}


def measured_net_saving(original_bytes, modified_bytes, *, accounting_complete,
                        includes_unique_ub_cost, includes_helper_cost, disjoint_components,
                        matched_workload_window):
    """Accept only complete totals. Never add Guest cache to RAM a second time.

    A caller declaring these flags is responsible for the actual measurement
    evidence. This function validates arithmetic, not the hardware observation.
    """
    gates = (accounting_complete, includes_unique_ub_cost, includes_helper_cost,
             disjoint_components, matched_workload_window)
    if any(value is not True for value in gates) or original_bytes is None or modified_bytes is None:
        return {'status': 'NA_GLOBAL_NET_NOT_MEASURED', 'saved_bytes': None, 'saving_fraction': None}
    original_bytes = uint(original_bytes, 'baseline total')
    modified_bytes = uint(modified_bytes, 'modified total')
    saved = original_bytes - modified_bytes
    return {'status': 'INPUT_TOTALS_COMPARED', 'saved_bytes': saved,
            'saving_fraction': saved / original_bytes if original_bytes else None,
            'original_bytes': original_bytes, 'modified_bytes': modified_bytes,
            'independent_hardware_attestation': False}
