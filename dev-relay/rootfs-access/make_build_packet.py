"""Package a pinned public original source tree plus the small observer delta."""
import argparse,base64,hashlib,importlib.util,json,subprocess,zlib
from pathlib import Path
HERE=Path(__file__).resolve().parent;REPO=HERE.parents[1]
def build(destination,rustfmt):
    spec=importlib.util.spec_from_file_location('access_candidate',HERE/'make_candidate.py')
    maker=importlib.util.module_from_spec(spec);spec.loader.exec_module(maker)
    changes,metadata=maker.prepare(destination,rustfmt)
    payload={name:dict(metadata[name],base64=base64.b64encode(raw).decode()) for name,raw in changes.items()}
    raw=subprocess.check_output(['git','archive','--format=tar',maker.BASE],cwd=REPO)
    archive={'sha256':hashlib.sha256(raw).hexdigest(),'base64':base64.b64encode(zlib.compress(raw,9)).decode()}
    lock=hashlib.sha256(maker.original('Cargo.lock')).hexdigest()
    digest=hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    prefix='"""Build-only packet: pinned public source; no workload or credentials."""\n'
    prefix+='BASE_COMMIT='+repr(maker.BASE)+'\nLOCK_SHA='+repr(lock)+'\nBASE_ARCHIVE='+repr(archive)+'\nPATCH_FILES='+repr(payload)+'\nPATCH_SHA='+repr(digest)+'\n'
    code=(HERE/'build_runtime.py').read_text(encoding='utf-8')
    footer='''
if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print('BEGIN_RETURN_REPORT')
        print(json.dumps({'status':'STOPPED_ROOTFS_ACCESS_BUILD_ENTRY','error_type':type(error).__name__,'reason':str(error)},indent=2))
        print('END_RETURN_REPORT')
        raise SystemExit(1)
'''
    packet=(prefix+code+footer).encode();path=REPO/'dev-relay/cow4_access_build.py';path.write_bytes(packet)
    info={'base_commit':maker.BASE,'archive_sha256':archive['sha256'],'lock_sha256':lock,'patch_sha256':digest,
        'script_sha256':hashlib.sha256(packet).hexdigest(),'script_bytes':len(packet),'changes':metadata}
    (destination/'build-packet.json').write_text(json.dumps(info,indent=2)+'\n',encoding='utf-8')
    return info
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('destination');p.add_argument('--rustfmt',required=True);a=p.parse_args()
    print(json.dumps(build(Path(a.destination),a.rustfmt),indent=2))
