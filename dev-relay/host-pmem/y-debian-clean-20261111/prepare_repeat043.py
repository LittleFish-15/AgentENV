import ast,base64,gzip,hashlib,json
from pathlib import Path
H=Path(__file__).resolve().parent
def sha(b):return hashlib.sha256(b).hexdigest()
def packed(b):return {'data':base64.b64encode(gzip.compress(b,mtime=0)).decode(),'sha256':sha(b),'bytes':len(b)}
def main():
 original=(H/'Y_diagnose041_bound.py').read_text();assert sha(original.encode())=='e9432bd0ebc3cc2bdb7669d8f0f1f21ae72035ffccc2c211e14ed17f362dff96'
 s=original.replace('import base64,gzip,hashlib,http.client,importlib.util,io,json,os,pathlib,pwd,re,signal,stat,subprocess,tarfile,time,uuid,fcntl','import base64,gzip,hashlib,http.client,importlib.util,io,json,os,pathlib,pwd,re,signal,stat,subprocess,tarfile,time,uuid,fcntl,sys')
 s=s.replace("W=B/'diagnosis-no-anchor-20261116-038'","ROUND=int(sys.argv[1]);assert 1<=ROUND<=6;W=B/'diagnostic-repeat-six-20261116-043'/('round-%02d'%ROUND)")
 s=s.replace("P('/run/jwk-aenv-y-clean-20261111/observer-code038')","P('/run/jwk-aenv-y-clean-20261111/observer-code043-r%02d'%ROUND)")
 start=s.index("  result['stage']='receive_diagnostic_client';")
 end=s.index('  template=',start)
 s=s[:start]+'''  result['stage']='copy_verified_existing_client'
  existing=B/'diagnosis-no-anchor-20261116-038/diagnostic-client';assert existing.resolve()==existing and existing.stat().st_uid==1002 and sha(existing)==BUILD['binarySha256']
  binary=existing.read_bytes();assert len(binary)==BUILD['binaryBytes'] and hashlib.sha256(binary).hexdigest()==BUILD['binarySha256'] and binary[:4]==b'\\x7fELF' and int.from_bytes(binary[18:20],'little')==62
  ownfile(W/'diagnostic-client',binary,0o700);save(W/'client-build-proof.json',BUILD);del binary
'''+s[end:]
 s=s.replace("included=[p for p in included if p.name not in ('result.json','archive-inventory.json')]","included=[p for p in included if p not in (W/'result.json',W/'archive-inventory.json')]")
 start=s.index("  try:\n   assert archive.stat().st_size<=128*800000")
 end=s.index("  save(W/'upload-summary.json',final)",start)
 s=s[:start]+"  final['archivePath']=str(archive);final['evidenceTransport']='raw archive retained on Y; small metrics via original entry receipt'\n"+s[end:]
 ast.parse(s,feature_version=(3,11));(H/'Y_diagnostic_round043.py').write_text(s,encoding='utf-8')
 tree=ast.parse((H/'analyze_run041.py').read_text());names={'PHASES','ROOTS','SERVICE','SANDBOX','INSTANCE','ENVD','COMMON','STAGES'}
 nodes=[n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id in names for t in n.targets) or isinstance(n,ast.FunctionDef) and n.name in ('stats','duration_ms','span_metrics')]
 helper='import math,re,statistics\nfrom collections import Counter,defaultdict\n'+ '\n'.join(ast.unparse(n) for n in nodes)
 pack={'worker':packed(s.encode()),'baseline':packed((H/'Y_run041.py').read_bytes()),'metrics':packed(helper.encode())}
 encoded=base64.b64encode(gzip.compress(json.dumps(pack).encode(),mtime=0)).decode();driver=(H/'Y_repeat043.py').read_text();assert driver.count('PACK=None')==1
 driver=driver.replace('PACK=None',"PACK=json.loads(gzip.decompress(base64.b64decode('"+encoded+"')))").encode();ast.parse(driver,feature_version=(3,11))
 (H/'Y_repeat043_bound.py').write_bytes(driver);proof={'sourceBytes':len(driver),'sourceSha256':sha(driver),'roundWorkerSha256':sha(s.encode()),'original041WorkerSha256':sha(original.encode()),'rounds':6,'sameClientBinary':True,'sameObserverAndMmap':True,'inlineBytes':len(base64.b64encode(driver))};(H/'repeat043-proof.json').write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps(proof))
if __name__=='__main__':main()
