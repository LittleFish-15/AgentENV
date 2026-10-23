"""Embed only the new public controller sources; reuse old pinned packets."""
import base64,hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent
def build():
    paths={name:HERE/(name+'.py') for name in ('patch_sources','root_measure','root_pair','owner_extension')}
    paths['root256_extra']=HERE.parent/'rootfs-io64/recheck256_root.py'
    data={}
    for name,path in paths.items():
        raw=path.read_bytes();compile(raw,str(path),'exec');data[name]={'sha256':hashlib.sha256(raw).hexdigest(),'base64':base64.b64encode(raw).decode()}
    prefix='"""Pinned two-group original AgentENV memory accounting relay."""\nimport base64,hashlib\nPAYLOADS='+repr(data)+'''
def payload(name):
    item=PAYLOADS[name];raw=base64.b64decode(item['base64'],validate=True)
    if hashlib.sha256(raw).hexdigest()!=item['sha256']:raise RuntimeError('Embedded helper differs')
    return raw.decode()
'''
    raw=(prefix+(HERE/'launch_pair.py').read_text(encoding='utf-8')).encode();compile(raw,'cow4-memory-pair','exec')
    path=HERE.parent/'cow4_memory_pair.py';path.write_bytes(raw);return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
if __name__=='__main__':print(json.dumps(build(),indent=2))
