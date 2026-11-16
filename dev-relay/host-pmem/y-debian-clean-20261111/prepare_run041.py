"""Freeze041 payload with verified source compression, not a Git transfer."""
import ast,base64,gzip,hashlib,json
from pathlib import Path
H=Path(__file__).resolve().parent
def sha(data):return hashlib.sha256(data).hexdigest()
def packed(data):return {'gzipBase64':base64.b64encode(gzip.compress(data,compresslevel=9,mtime=0)).decode(),'bytes':len(data),'sha256':sha(data)}
def main():
 original=(H/'Y_diagnose038_bound.py').read_bytes();assert sha(original)=='33a6e0ffde32517f7c74c87d759aafadbb6a5b3a18a12442882dd40847449bc0'
 before=b"assert drop.read_text()==body;drop.unlink();cmd(['systemctl','daemon-reload']);cmd(['systemctl','restart',U],120)"
 after=b"assert drop.read_text()==body;drop.unlink();cmd(['systemctl','daemon-reload']);assert inventory()==[],'New sandboxes appeared; refusing final service restart';cmd(['systemctl','restart',U],120)"
 assert original.count(before)==1;diagnostic=original.replace(before,after);ast.parse(diagnostic,feature_version=(3,11));(H/'Y_diagnose041_bound.py').write_bytes(diagnostic)
 bundle={}
 for name,expected in [('auth_proxy010.py','93c9c7be94afe35a33bf471bd93c9656e5525d2893ce88be208870aa4a72f52c'),('device_broker017.py','5bfe4f7c36054f57e29d557e34a2748b21691887842fe2efc65839094356913a')]:
  data=(H/name).read_bytes();assert sha(data)==expected;bundle[name]={'base64':base64.b64encode(data).decode(),'sha256':sha(data)}
 restore=(H/'Y_restore041.py').read_bytes();ast.parse(restore,feature_version=(3,11));pack={'restore':packed(restore),'diagnostic':packed(diagnostic),'bundle':bundle,'archived038OriginalSha256':sha(original)}
 encoded=base64.b64encode(gzip.compress(json.dumps(pack,separators=(',',':')).encode(),compresslevel=9,mtime=0)).decode()
 source=(H/'Y_run041.py').read_text();assert source.count('PACK=None')==1;worker=source.replace('PACK=None',"PACK=json.loads(gzip.decompress(base64.b64decode('"+encoded+"')))").encode();ast.parse(worker,feature_version=(3,11));assert len(worker)<=256*1024
 (H/'Y_run041_bound.py').write_bytes(worker);proof={'sourceBytes':len(worker),'sourceSha256':sha(worker),'restoreSourceSha256':sha(restore),'diagnosticSourceSha256':sha(diagnostic),'archived038OriginalSha256':sha(original),'requestImplementationUnchanged':True,'inlineBase64Bytes':len(base64.b64encode(worker))};(H/'run041-build-proof.json').write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps(proof))
if __name__=='__main__':main()
