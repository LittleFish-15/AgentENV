"""Read retained private replay and snapshot identities without reading payload.

The executable caller supplies the pinned ordinary file reader and replay
parser. No workload text is included in returned public evidence.
"""
import base64
import hashlib
import json
from pathlib import Path


SEED_SHA = {
    'a':'6247c51df4993d5a6935b7112567989bb189cff2bcf69e874d0154207b0ced15',
    'b':'91d33a86fb12ffa75e6b6af70f327566fc39ac9d7e79e362fbfa0e96a68f2294'}


def need(ok, reason):
    if not ok: raise RuntimeError(reason)


def load_inputs(source, node, count, read, steps_from):
    need(node in SEED_SHA and count in (1,4), 'Explicit node and template scope required')
    raw = read(source/'rootfs-inputs.json')
    need(hashlib.sha256(raw).hexdigest() == SEED_SHA[node], 'Retained seed changed')
    seed = json.loads(raw)
    need(seed['status'] == 'ORDINARY_FOUR_SNAPSHOTS_SEEDED_NOT_GUEST_ACCEPTANCE'
         and seed['node'] == 'node-'+node, 'Retained seed role differs')
    directory = Path(seed['inputDirectory'])
    raw = read(directory/'manifest.json')
    need(hashlib.sha256(raw).hexdigest() == seed['sourceManifestSha256'], 'Input manifest changed')
    manifest = json.loads(raw)
    raw = read(directory/'selection.private.json', 8*1024**2)
    need(hashlib.sha256(raw).hexdigest() == manifest['files']['selection.private.json']['sha256'], 'Private selection changed')
    selected = json.loads(raw)['selected']
    need(len(selected) == len(seed['templates']) == 4, 'Four retained template identities required')
    steps = {}
    for index, (case, template) in enumerate(zip(selected, seed['templates'])):
        need(template['templateIndex'] == index and case['original']['template_id'] == template['templateId']
             and case['case']['instance_id'] == template['instanceId']
             and case['case']['replay_sha256'] == template['replaySha256'], 'Retained template/replay association differs')
        if index >= count: continue
        raw = base64.b64decode(case['replayBase64'], validate=True)
        need(hashlib.sha256(raw).hexdigest() == template['replaySha256'], 'Decoded replay changed')
        steps[index], _ = steps_from(raw)
        need(len(steps[index]) == case['executedStepCount'], 'Executable command count differs')
    return seed['templates'][:count], steps


def check_catalogs(base, templates, read):
    """Check committed rootfs/resources; no snapshot or payload is copied."""
    for template in templates:
        record = base/'state/snapshot-store/repository/catalog/records'/(template['templateId']+'.json')
        raw = read(record)
        need(hashlib.sha256(raw).hexdigest() == template['catalogSha256'], 'Runtime catalog differs from retained seed')
        value = json.loads(raw)
        need(value['id'] == template['templateId'] and value['resources'] == template['resources'], 'Catalog identity/resources differ')
        roots = value['committed']['rootfs_layers']
        need(all(isinstance(row,dict) and set(row)=={'Managed'} for row in roots), 'Unexpected rootfs layer kind')
        need([row['Managed'] for row in roots] == template['rootfsLayers'], 'Catalog committed lower sequence differs')


def lower_file_scope(original, source, templates, identity):
    """Stat both actual repositories; never fault ordinary lower contents."""
    rows = []
    selected = {}
    for template in templates:
        for layer in template['rootfsLayers']:
            need(layer['digest'] not in selected or selected[layer['digest']] == layer['size'], 'Conflicting lower length')
            selected[layer['digest']] = layer['size']
    import stat
    for base, category in ((original,'rootfs-lower-original'),(source,'rootfs-lower-ub-source')):
        for digest,size in selected.items():
            path = base/'state/snapshot-store/repository/managed-layers'/(digest.replace(':','_')+'.overlaybd.commit')
            need(path.resolve(strict=True)==path, 'Lower source path redirected')
            meta=path.stat()
            need(stat.S_ISREG(meta.st_mode) and meta.st_uid==1204 and meta.st_size==size, 'Lower source identity differs')
            rows.append({'path':str(path),'identity':identity(meta),'category':category,
                         'immutable':True,'contentDigest':digest})
    return rows


def memory_file_scope(original, source, templates, read, identity):
    """Memory snapshot ordinary files are separate from Guest RAM/device cache."""
    import stat
    rows={}
    for base in (original,source):
        for template in templates:
            raw=read(base/'state/snapshot-store/repository/catalog/records'/(template['templateId']+'.json'))
            need(hashlib.sha256(raw).hexdigest()==template['catalogSha256'], 'Memory catalog differs')
            for entry in json.loads(raw)['committed']['memory_layers']:
                # Committed memory layers are ManagedLayer structs directly;
                # only rootfs layers use the externally tagged Managed enum.
                need(isinstance(entry,dict) and set(entry)>={'digest','size'}, 'Unsupported memory layer kind')
                layer=entry
                path=base/'state/snapshot-store/repository/managed-layers'/(layer['digest'].replace(':','_')+'.overlaybd.commit')
                need(path.resolve(strict=True)==path, 'Memory source redirected')
                meta=path.stat()
                need(stat.S_ISREG(meta.st_mode) and meta.st_uid==1204 and meta.st_size==layer['size'], 'Memory source metadata differs')
                key=(meta.st_dev,meta.st_ino)
                row={'path':str(path),'identity':identity(meta),'category':'memory-lower','immutable':True,
                     'contentDigest':layer['digest']}
                if key in rows:need(rows[key]['contentDigest']==layer['digest'],'Aliased memory lower content differs')
                else:rows[key]=row
    return list(rows.values())
