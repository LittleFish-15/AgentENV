"""Developer-only deterministic single-file packaging of public relay sources."""
import base64, hashlib, json
from pathlib import Path
HERE=Path(__file__).resolve().parent
def build():
    payload={}
    for name in ('cow55_replay','cow55_reader','cow33_selection'):
        raw=(HERE/(name+'.py')).read_bytes()
        payload[name]={'sha256':hashlib.sha256(raw).hexdigest(),'base64':base64.b64encode(raw).decode()}
    driver=(HERE/'cow33_driver.py').read_text(encoding='utf-8')
    preamble='''"""Single-file original CoW relay; packaged public sources, no workload data."""
import base64, hashlib, json, sys, types
EMBEDDED = '''+repr(payload)+'''
def _embedded(name):
    item=EMBEDDED[name];raw=base64.b64decode(item['base64'],validate=True)
    if hashlib.sha256(raw).hexdigest()!=item['sha256']:raise RuntimeError('Embedded source differs')
    return raw
def _module(name):
    value=types.ModuleType(name);value.__file__=__file__+'#'+name
    sys.modules[name]=value;exec(compile(_embedded(name),value.__file__,'exec'),value.__dict__);return value
ENGINE=_module('cow55_replay')
SELECTOR=_module('cow33_selection')
READER_SOURCE=_embedded('cow55_reader').decode('utf-8')
'''
    footer='''
if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print('BEGIN_RETURN_REPORT')
        print(json.dumps({'status':'STOPPED_COW33_ENTRY','error_type':type(error).__name__,'reason':str(error)},indent=2))
        print('END_RETURN_REPORT')
        raise SystemExit(1)
'''
    raw=(preamble+'\n'+driver+'\n'+footer).encode('utf-8')
    (HERE/'cow33_once.py').write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()
if __name__=='__main__':print(build())
