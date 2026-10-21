"""Package reviewed public controllers; no private workload or binary payload."""
import base64, hashlib
from pathlib import Path

HERE=Path(__file__).resolve().parent
RELAY=HERE.parent


def build():
    payload={}
    for name,path in [('engine',RELAY/'cow55_replay.py'),('accounting',HERE/'page_accounting.py'),
                      ('process_summary',RELAY/'cow55_process_summary.py'),('root_session',HERE/'root_session.py')]:
        raw=path.read_bytes()
        if name=='engine':
            old=b'template_count in (16,17,55)'
            assert raw.count(old)==1
            raw=raw.replace(old,b'template_count in (4,16,17,55)')
        payload[name]={'sha256':hashlib.sha256(raw).hexdigest(),'base64':base64.b64encode(raw).decode()}
    preamble='''"""Four-template original access replay. Private trajectories stay on A."""
import base64,hashlib,sys,types
EMBEDDED = '''+repr(payload)+'''
def _source(name):
    item=EMBEDDED[name];raw=base64.b64decode(item['base64'],validate=True)
    if hashlib.sha256(raw).hexdigest()!=item['sha256']:raise RuntimeError('Embedded source differs')
    return raw.decode()
def _module(name):
    value=types.ModuleType('cow4_'+name);value.__file__=__file__+'#'+name
    sys.modules[value.__name__]=value;exec(compile(_source(name),value.__file__,'exec'),value.__dict__);return value
ENGINE=_module('engine')
ACCOUNTING=_module('accounting')
PROCESS=_module('process_summary')
ROOT_SOURCE=_source('root_session')
'''
    footer='''
if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print('BEGIN_RETURN_REPORT')
        print(json.dumps({'status':'STOPPED_COW4_ACCESS_ENTRY','error_type':type(error).__name__,'reason':str(error)},indent=2))
        print('END_RETURN_REPORT')
        raise SystemExit(1)
'''
    raw=(preamble+(HERE/'four_run.py').read_text(encoding='utf-8')+footer).encode()
    (RELAY/'cow4_access_once.py').write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


if __name__=='__main__':print(build())
