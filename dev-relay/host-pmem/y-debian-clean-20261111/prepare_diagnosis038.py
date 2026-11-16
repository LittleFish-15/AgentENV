"""Package locally built linux/amd64 diagnostic assets without remote access."""
import ast,base64,gzip,hashlib,json
from pathlib import Path
H=Path(__file__).resolve().parent
def digest(raw):return hashlib.sha256(raw).hexdigest()
def main():
 raw=(H/'diagnostic038-client').read_bytes()
 assert raw[:4]==b'\x7fELF' and int.from_bytes(raw[18:20],'little')==62
 assert b'C:/2026/' not in raw and b'C:\\2026\\' not in raw,'Missing trimpath'
 zipped=gzip.compress(raw,compresslevel=9,mtime=0)
 names=[]
 for index,start in enumerate(range(0,len(zipped),800000)):
  name='diagnostic038.part%02d.bin'%index;(H/name).write_bytes(zipped[start:start+800000]);names.append(name)
 proof=json.loads((H/'diagnostic038-source-proof.json').read_text())
 proof.update(binaryBytes=len(raw),binarySha256=digest(raw),compressedBytes=len(zipped),compressedSha256=digest(zipped),binaryParts=names,compiler='go1.27.4 windows/amd64',buildFlags=['-trimpath'],GOOS='linux',GOARCH='amd64',CGO_ENABLED='0')
 wrapper=(H/'runtime_supervisor025.py').read_bytes();marker=b',agentenv::sandbox::envd=trace';assert wrapper.count(marker)==1
 wrapper=wrapper.replace(marker,b'');(H/'runtime_diagnostic038.py').write_bytes(wrapper)
 for name in ('Y_diagnose038.py','observer038.py','mmap_probe038.py','runtime_diagnostic038.py'):
  data=(H/name).read_bytes();ast.parse(data,feature_version=(3,11))
 proof['wrapperSourceSha256']=digest((H/'runtime_supervisor025.py').read_bytes());proof['diagnosticWrapperSha256']=digest(wrapper)
 (H/'diagnostic038-build-proof.json').write_text(json.dumps(proof,indent=2)+'\n')
 collector=H/'collect.py';source=collector.read_text();old="['debian-runtime037-publication.private.json'";new="['debian-runtime038-publication.private.json','debian-runtime037-publication.private.json'"
 if new not in source:assert source.count(old)==2;collector.write_text(source.replace(old,new))
 collector=H.parent/'y-jwk-aenv-20261107/collect_job.py';source=collector.read_text();old="'debian-runtime037-publication.private.json'),'Unknown publication packet')";new="'debian-runtime037-publication.private.json','debian-runtime038-publication.private.json'),'Unknown publication packet')"
 if new not in source:assert source.count(old)==1;collector.write_text(source.replace(old,new))
 print(json.dumps({'binaryBytes':len(raw),'compressedBytes':len(zipped),'parts':len(names),'architecture':'linux/amd64','requestImplementationByteIdentical':proof['requestImplementationByteIdentical']}))
if __name__=='__main__':main()
