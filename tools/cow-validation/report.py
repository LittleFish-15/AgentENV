#!/usr/bin/env python3
"""Generate a comparison from existing evidence, without contacting any node."""
import argparse
import base64
from collections import defaultdict
import json
from pathlib import Path
import zlib

MIB = 1024 * 1024


def read_json(path):
    with Path(path).open('rb') as stream:
        raw = stream.read(8 * MIB + 1)
    if len(raw) > 8 * MIB:
        raise ValueError('Evidence exceeds 8MiB')
    return json.loads(raw)


def amount(value):
    if value is None:
        return 'NA'
    if isinstance(value, list):
        return '～'.join(f'{item / MIB:.4f}' for item in value)
    return f'{value / MIB:.4f}'


def ratio(value):
    if value is None:
        return 'NA'
    if isinstance(value, list):
        return '～'.join(f'{item * 100:.2f}%' for item in value)
    return f'{value * 100:.2f}%'


def cache_intersections(samples):
    """Common resident offsets are a reuse opportunity, not global physical saving."""
    groups = defaultdict(list)
    for sample in samples:
        groups[(sample['experimentId'], sample['variant'], sample['phase'])].append(sample)
    observations = []
    for identity, values in groups.items():
        if len(values) != 2 or values[0]['nodeId'] == values[1]['nodeId']:
            continue
        if values[0]['pageBytes'] != values[1]['pageBytes']:
            raise ValueError('Different page sizes require explicit byte-range normalization')
        page = values[0]['pageBytes']
        by_node = []
        complete = True
        for value in values:
            selected = {}
            for entry in value['files']:
                if entry.get('kind') != 'rootfsLower':
                    continue
                if 'offsetBitmapZlibBase64' not in entry:
                    complete = False
                    continue
                size = entry['fileBytes']
                if type(size) is not int or not 0 < size <= 2 * 1024**3:
                    raise ValueError('Unbounded cache bitmap input')
                count = (size + page - 1) // page
                decoder = zlib.decompressobj()
                bits = decoder.decompress(base64.b64decode(entry['offsetBitmapZlibBase64'], validate=True), count + 1)
                if not decoder.eof or decoder.unused_data or len(bits) != count or any(bit not in (0, 1) for bit in bits):
                    raise ValueError('Invalid bounded cache offset bitmap')
                key = entry['sha256'], size
                if key in selected and selected[key] != bits:
                    raise ValueError('Ambiguous same-digest cache objects on one node')
                selected[key] = bits
            by_node.append(selected)
            if not selected:
                complete = False
        common = set(by_node[0]) & set(by_node[1])
        bytes_common = sum(sum(a & b for a, b in zip(by_node[0][key], by_node[1][key])) * page for key in common)
        observations.append({'experimentId': identity[0], 'variant': identity[1], 'phase': identity[2],
                             'commonRootfsResidentOffsetBytes': bytes_common if complete else None,
                             'observedPartialOffsetBytes': bytes_common if common else None,
                             'listedRootfsCoverageComplete': complete,
                             'coverage': 'intersection of listed digest/length ranges only',
                             'netPhysicalSavedBytes': None})
    return observations


def render(evidence, samples):
    intersections = cache_intersections(samples)
    lines = ['# Cross-node CoW evidence report', '',
             'This report summarizes explicitly supplied evidence; it does not run or certify a node experiment.',
             'Native RAM CoW, Guest DAX, cross-node reuse and complete physical accounting require separate acceptance.', '',
             '| Variant | Phase | Valid RAM samples | Shared unique MiB | Shared participation | Avoided duplicates | Rootfs lower resident MiB |',
             '| --- | --- | --- | --- | --- | --- | --- |']
    for variant in evidence.get('variants', []):
        for phase in variant.get('phases', []):
            lines.append(f"| {variant.get('name', 'NA')} | {phase.get('phase', 'NA')} | {phase.get('validRamSamples', 'NA')} | {amount(phase.get('guestRamSharedUniqueBytes'))} | {ratio(phase.get('participationRatio'))} | {ratio(phase.get('avoidanceRatio'))} | {amount(phase.get('rootfsLowerResidentBytes'))} |")
    lines += ['', '## Explicit additional samples', '']
    if not samples:
        lines.append('No new node samples supplied.')
    for sample in samples:
        sharing = sample.get('guestRamSharing')
        lines.append(f"- {sample['nodeId']} / {sample['variant']} / {sample['phase']}: " +
                     (f"shared unique Guest RAM {amount(sharing['sharedUniqueBytes'])} MiB." if sharing else 'RAM physical evidence unavailable: NA.'))
    for item in intersections:
        lines.append(f"- {item['variant']} / {item['phase']}: listed common resident rootfs offsets {amount(item['commonRootfsResidentOffsetBytes'])} MiB; this is an opportunity, not physical saving.")
    lines += ['', '## Physical accounting boundary', '',
              'Net physical saving: NA. Compare the same inputs, workload, concurrency and sampling points.',
              'Count the real UB allocation once, node-local copies/caches, private Guest pages, uppers and helpers. Avoid overlapping counters; Guest filesystem cache is already in Guest RAM.',
              'PFNs are comparable only within one node/boot. SDK logical bytes/coverage, equal hashes, traffic and RSS alone do not establish net savings.', '',
              '## Declared evidence sources', '']
    for source in evidence.get('sources', []):
        lines.append(f"- {source.get('name', 'unnamed')}: SHA256 {source.get('sha256', 'NA')}; scope: {source.get('scope', 'unspecified')}.")
    return '\n'.join(lines) + '\n', intersections


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', required=True, help='Explicit normalized version-1 evidence JSON; no bundled laboratory defaults')
    parser.add_argument('--sample', action='append', default=[])
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    evidence = read_json(args.evidence)
    if evidence.get('version') != 1:
        raise ValueError('Unsupported normalized evidence bundle')
    samples = [read_json(path) for path in args.sample]
    text, opportunities = render(evidence, samples)
    output = Path(args.output)
    output.mkdir(exist_ok=False)
    (output / 'report.md').write_text(text, encoding='utf-8')
    (output / 'result.json').write_text(json.dumps({'status': 'REPORT_FROM_EXISTING_EVIDENCE',
        'newNodeContactPerformed': False, 'nativeMemfileAccepted': False, 'nativeRootfsAccepted': False,
        'netPhysicalSavedBytes': None, 'netPhysicalSavedRatio': None,
        'rootfsOffsetOpportunities': opportunities}, indent=2), encoding='utf-8')
    print(str(output / 'report.md'))


if __name__ == '__main__':
    main()
