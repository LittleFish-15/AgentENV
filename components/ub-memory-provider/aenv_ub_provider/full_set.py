"""Plan full stored-layer extension and compose existing provider indexes.

No SDK calls, source payload reads or new parent-owner relationship. Existing
objects remain served by their existing brokers; only missing contents are
published by a separate ordinary stored-direct provider.
"""
import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import re

from . import service, stored
from .io import atomic_json


def require(ok, message):
    if not ok:
        raise ValueError(message)


def semantic(replica):
    return {key: value for key, value in asdict(replica).items() if key != 'brokerSocket'}


def validate_fragment(manifest, index):
    require(isinstance(manifest, dict) and set(manifest) == {'version','ownerId','mode','readers','replicas'}
            and type(manifest['version']) is int and manifest['version'] == 1
            and manifest['mode'] == 'stored-direct', 'Expected full stored-direct publication')
    require(isinstance(manifest['ownerId'], str) and re.fullmatch('[0-9a-f]{32}', manifest['ownerId']), 'Invalid owner identity')
    service.names(manifest['readers'])
    require(isinstance(index, dict) and set(index) == {'version','state','replicas'}
            and type(index['version']) is int and index['version'] == 1 and index['state'] == 'ready', 'Expected ready runtime index')
    refs = [stored.Replica(**row).validate() for row in index['replicas']]
    require(1 <= len(refs) <= 64 and len(refs) == len(manifest['replicas']), 'Invalid fragment size')
    require(len({r.objectName for r in refs}) == len({r.layerDigest for r in refs}) == len(refs), 'Duplicate object/content in fragment')
    require(len({r.brokerSocket for r in refs}) == 1, 'One fragment must describe one existing broker')
    require(all(not r.allowRepositoryFallback for r in refs), 'Full set forbids repository fallback')
    expected = sorted(manifest['replicas'], key=lambda row: row['objectName'])
    actual = sorted((semantic(r) for r in refs), key=lambda row: row['objectName'])
    require(actual == expected, 'Runtime index differs from publication object/generation identity')
    return refs


def plan_extension(sources, retained_manifest, retained_index, retained_coverage_bytes,
                   coverage_quantum_bytes, total_coverage_budget):
    """Metadata-only plan. Coverage quantum is a projection, not a quota."""
    refs = validate_fragment(retained_manifest, retained_index)
    require(type(retained_coverage_bytes) is int and retained_coverage_bytes >= sum(r.mappingBytes for r in refs),
            'Reported retained coverage missing or below mapped content')
    require(type(coverage_quantum_bytes) is int and coverage_quantum_bytes >= stored.ALIGN
            and coverage_quantum_bytes % stored.ALIGN == 0, 'Explicit aligned coverage estimate required')
    require(type(total_coverage_budget) is int and total_coverage_budget > 0, 'Explicit total coverage budget required')
    require(1 <= len(sources) <= 64, 'Expected bounded unique immutable contents')
    old = {r.layerDigest: r for r in refs}
    require(set(old) <= set(sources), 'Retained set contains unexpected contents')
    expected, missing, aligned = [], [], 0
    for digest, (path, size) in sources.items():
        require(re.fullmatch('sha256:[0-9a-f]{64}', digest) and type(size) is int and size > 0, 'Invalid content identity')
        expected.append({'digest': digest, 'size': size})
        if digest in old:
            require(old[digest].fileBytes == size, 'Retained content length differs')
        else:
            require(path is not None and Path(path).is_absolute(), 'Missing new source path')
            mapping = (size + stored.HEADER_BYTES + stored.ALIGN - 1) // stored.ALIGN * stored.ALIGN
            aligned += mapping
            missing.append({'digest': digest, 'size': size, 'file': str(path), 'mappingBytes': mapping,
                            'projectedCoverageBytes': (mapping + coverage_quantum_bytes - 1) // coverage_quantum_bytes * coverage_quantum_bytes})
    projected = sum(row['projectedCoverageBytes'] for row in missing)
    return {'format': 'aenv-full-extension-v1', 'expectedContents': expected,
            'retainedOwnerId': retained_manifest['ownerId'], 'retainedManifestSha256': service.identity(retained_manifest),
            'retainedReplicas': [semantic(r) for r in refs], 'newLayers': missing,
            'retainedReportedCoverageBytes': retained_coverage_bytes, 'newMappingBytes': aligned,
            'newCoverageBudgetBytes': max(0, total_coverage_budget - retained_coverage_bytes),
            'coverageQuantumBytes': coverage_quantum_bytes, 'newProjectedCoverageBytes': projected,
            'projectedTotalCoverageBytes': retained_coverage_bytes + projected,
            'totalCoverageBudgetBytes': total_coverage_budget,
            'withinDeclaredBudget': retained_coverage_bytes + projected <= total_coverage_budget,
            'SDKCalled': False, 'newAllocations': 0, 'physicalHardQuota': False,
            'scope': 'missing-content plan only; publication and actual post-map coverage remain unverified'}


def publication_input(plan):
    require(plan['format'] == 'aenv-full-extension-v1' and plan['withinDeclaredBudget'] is True,
            'Extension exceeds declared total budget; no publication input emitted')
    projected = plan['retainedReportedCoverageBytes'] + sum(row['projectedCoverageBytes'] for row in plan['newLayers'])
    require(projected == plan['projectedTotalCoverageBytes'] <= plan['totalCoverageBudgetBytes'], 'Coverage budget changed')
    require(plan['newLayers'], 'No missing contents; reuse existing index without new provider')
    return {'purpose': 'publication-only-missing-stored-layers-not-a-guest-image',
            'lowers': [{k: row[k] for k in ('digest','size','file')} for row in plan['newLayers']]}


def compose(plan, fragments, reader_id=None):
    require(plan['format'] == 'aenv-full-extension-v1' and 1 <= len(fragments) <= 8, 'Invalid full-set plan/fragments')
    require(plan['withinDeclaredBudget'] is True
            and plan['projectedTotalCoverageBytes'] <= plan['totalCoverageBudgetBytes'], 'Full set exceeds declared budget')
    expected = {row['digest']: row['size'] for row in plan['expectedContents']}
    require(len(expected) == len(plan['expectedContents']), 'Duplicate expected contents')
    refs, groups, names, owners, sockets = {}, [], set(), set(), set()
    retained_seen = False
    for manifest, index in fragments:
        rows = validate_fragment(manifest, index)
        require(manifest['ownerId'] not in owners, 'Duplicate publication owner')
        require(rows[0].brokerSocket not in sockets, 'Different owners alias one broker socket')
        if reader_id is not None:
            require(reader_id in manifest['readers'], 'Importer is not registered for every owner')
        owners.add(manifest['ownerId']); sockets.add(rows[0].brokerSocket)
        for row in rows:
            require(row.layerDigest in expected and row.fileBytes == expected[row.layerDigest], 'Unrequested or changed lower content')
            require(row.layerDigest not in refs and row.objectName not in names, 'Duplicate allocation/content across owners')
            refs[row.layerDigest] = row; names.add(row.objectName)
        if manifest['ownerId'] == plan['retainedOwnerId']:
            require(service.identity(manifest) == plan['retainedManifestSha256']
                    and sorted((semantic(row) for row in rows), key=lambda r: r['objectName'])
                    == sorted(plan['retainedReplicas'], key=lambda r: r['objectName']), 'Retained owner/objects were replaced')
            retained_seen = True
        groups.append({'ownerId': manifest['ownerId'], 'manifestSha256': service.identity(manifest),
                       'brokerSocket': rows[0].brokerSocket, 'readers': manifest['readers'],
                       'objects': sorted(row.objectName for row in rows)})
    require(retained_seen and set(refs) == set(expected), 'Incomplete exact full-set coverage')
    ordered = [refs[row['digest']] for row in plan['expectedContents']]
    return {'runtimeIndex': stored.index_for(ordered), 'owners': groups,
            'contentSetSha256': service.identity(sorted((semantic(row) for row in ordered), key=lambda r: r['layerDigest'])),
            'SDKCalled': False, 'objectsCopied': 0, 'ownerRetirementCombined': False,
            'metadataOnly': True, 'liveLeasesAttested': False,
            'releaseRule': 'Keep each owner independently; its local Runtime/daemon leases and all its configured importer receipts must drain before its own retirement'}


def read_fragment(descriptor):
    require(set(descriptor) == {'manifest','manifestSha256','index','indexSha256'}, 'Explicit fragment paths and pins required')
    def read(path):
        path=Path(path)
        require(path.is_absolute() and path.resolve(strict=True)==path, 'Redirected fragment path')
        with path.open('rb') as stream: raw=stream.read(1024**2+1)
        require(len(raw)<=1024**2, 'Fragment exceeds bounded metadata size')
        return raw
    manifest=json.loads(read(descriptor['manifest']))
    require(service.identity(manifest)==descriptor['manifestSha256'], 'Publication manifest pin differs')
    raw=read(descriptor['index'])
    require(hashlib.sha256(raw).hexdigest()==descriptor['indexSha256'].removeprefix('sha256:'), 'Runtime index pin differs')
    index=json.loads(raw);validate_fragment(manifest,index)
    return manifest,index


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='operation',required=True)
    plan=sub.add_parser('plan');plan.add_argument('--image',action='append',required=True)
    plan.add_argument('--source-root',required=True);plan.add_argument('--retained-fragment',required=True)
    plan.add_argument('--retained-coverage-bytes',type=int,required=True)
    plan.add_argument('--coverage-quantum-bytes',type=int,required=True)
    plan.add_argument('--total-coverage-budget',type=int,required=True)
    plan.add_argument('--output',required=True)
    merge=sub.add_parser('compose');merge.add_argument('--plan',required=True);merge.add_argument('--plan-sha256',required=True)
    merge.add_argument('--fragment',action='append',required=True);merge.add_argument('--reader-id')
    merge.add_argument('--output',required=True)
    args=parser.parse_args();out=Path(args.output)
    require(out.is_absolute() and out.resolve()==out and out.parent.is_dir() and not out.exists(), 'Fresh absolute output directory required')
    from .io import read_json
    if args.operation=='plan':
        manifest,index=read_fragment(read_json(args.retained_fragment))
        sources=stored.source_layers(args.image,source_root=args.source_root)
        result=plan_extension(sources,manifest,index,args.retained_coverage_bytes,args.coverage_quantum_bytes,args.total_coverage_budget)
        out.mkdir(mode=0o700)
        atomic_json(out/'plan.json',result)
        if result['withinDeclaredBudget'] and result['newLayers']:
            atomic_json(out/'new-layer-publication-input.json',publication_input(result))
        print(json.dumps({'state':'extension_planned_no_sdk','planSha256':service.identity(result),
            'uniqueLayers':len(result['expectedContents']),'newLayers':len(result['newLayers']),
            'projectedTotalCoverageBytes':result['projectedTotalCoverageBytes'],
            'withinDeclaredBudget':result['withinDeclaredBudget']}))
    else:
        value=read_json(args.plan)
        require(service.identity(value)==args.plan_sha256,'Extension plan pin differs')
        result=compose(value,[read_fragment(read_json(path)) for path in args.fragment],args.reader_id)
        out.mkdir(mode=0o700)
        atomic_json(out/'runtime-index.json',result['runtimeIndex'])
        raw=(out/'runtime-index.json').read_bytes()
        result['runtimeIndexSha256']=hashlib.sha256(raw).hexdigest()
        atomic_json(out/'composition.json',result)
        print(json.dumps({'state':'full_set_metadata_composed_not_deployed','owners':len(result['owners']),
            'layers':len(result['runtimeIndex']['replicas']),'runtimeIndexSha256':result['runtimeIndexSha256'],
            'contentSetSha256':result['contentSetSha256'],'liveLeasesAttested':False}))
    return 0

if __name__=='__main__':raise SystemExit(main())
