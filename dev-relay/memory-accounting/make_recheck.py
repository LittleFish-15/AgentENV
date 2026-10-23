from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent
def build():
    owner=(HERE/'recheck256_owner.py').read_text(encoding='utf-8');compile(owner,'repeat-owner','exec')
    source='REPEAT_OWNER='+repr(owner)+'\n'+(HERE/'recheck256_launch.py').read_text(encoding='utf-8')
    compile(source,'memory-repeat-packet','exec');raw=source.encode();(HERE.parent/'cow4_memory_recheck256.py').write_bytes(raw)
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
if __name__=='__main__':print(json.dumps(build(),indent=2))
