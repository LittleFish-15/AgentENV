"""Prepare trusted demand metadata from retained rootfs layers, without UB.

This explicit preparation scans source bytes via O_DIRECT for identity. Runtime
startup and metadata handshakes do not perform that scan or allocate content.
The catalog contains private source paths; never publish it as public code.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path

from . import contract, stored
from .demand_source import DirectSource, build_manifest
from .host_dax_demand import canonical, require
from .io import atomic_json


def prepare(images, source_root, output):
    contract.linux_only()
    source_root=Path(source_root)
    require(source_root.is_absolute() and source_root.resolve(strict=True)==source_root,
            'Explicit unredirected source boundary required')
    sources=stored.source_layers(images,source_root=source_root)
    target=Path(output)
    require(target.is_absolute() and target.parent.resolve(strict=True)==target.parent
            and not target.exists() and not target.is_symlink(),'New private catalog directory required')
    target.mkdir(mode=0o700)
    atomic_json(target/'preparation.json',{'phase':'SOURCE_HASH_INTENT','SDK_called':False,
                'sourceLayers':len(sources),'sourceBytes':sum(size for _,size in sources.values())})
    manifests=[]
    for digest,(path,size) in sources.items():
        source=DirectSource(path,size)
        try:
            document,pin=build_manifest(source,expected_layer_digest=digest)
            row={'sha256':pin,'document':document,'sourcePath':str(path),
                 'sourceIdentity':list(source.identity),'directReadBytes':source.direct_bytes}
        finally:source.close()
        atomic_json(target/(pin+'.json'),row)
        manifests.append(row)
    catalog={'version':1,'state':'TRUSTED_MANIFESTS_PREPARED_NO_UB','manifests':manifests,
             'SDK_called':False,'moduleChanged':False,'Guest_created':False,
             'sourceScanIsPreparationNotRuntimeDemand':True}
    raw=canonical(catalog)
    require(len(raw)<=768*1024,'Catalog exceeds runtime envelope; preserve prepared manifests')
    atomic_json(target/'catalog.json',catalog)
    result={'state':catalog['state'],'catalogSha256':hashlib.sha256(raw).hexdigest(),
            'layers':len(manifests),'sourceBytes':sum(size for _,size in sources.values()),
            'sourceDirectReadBytes':sum(row['directReadBytes'] for row in manifests),
            'SDK_called':False,'UBObjectsCreated':0}
    atomic_json(target/'preparation.json',dict(result,phase='COMPLETE'))
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-config',action='append',required=True)
    parser.add_argument('--source-root',required=True)
    parser.add_argument('--output',required=True)
    args=parser.parse_args()
    print(json.dumps(prepare(args.image_config,args.source_root,args.output)))


if __name__=='__main__':main()
