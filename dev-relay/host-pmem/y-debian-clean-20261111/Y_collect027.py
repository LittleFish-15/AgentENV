"""Read-only recovery of existing026 result, split below1MiB local output bound."""
import base64,hashlib,http.client,json,os,pathlib,sys
P=pathlib.Path;BASE=P('/home/jwk/aenv-y-clean-20261111');D=BASE/'diagnostic026';SIZE=400000
def main():
 assert os.getuid()==os.geteuid()==0 and sys.argv[1:] in (['meta'],['0'],['1'],['2'])
 path=D/'result.json';mode=sys.argv[1];result=None
 if path.is_file():
  assert not path.is_symlink() and path.stat().st_size<4*1024**2
  result=json.loads(path.read_text())
 if mode=='meta':
  output={'action':'READONLY_EXISTING026_RECOVERY','originalResultPresent':result is not None,'experimentRerun':False}
  if result is not None:
   output['result']={k:v for k,v in result.items() if k!='archive'}
   a=result.get('archive');output['archive']={k:v for k,v in a.items() if k!='base64'} if a else None
  local=BASE.parent/'y-aenv-control/relay-debian-clean-20261111/jobs/y-debian-anchor-memory-ab-20261112-026-node-y'
  output['originalEntryFiles']={n:{'bytes':(local/n).stat().st_size} for n in ('state.json','report.json','stdout.log','stderr.log') if (local/n).is_file()}
  if (local/'state.json').is_file():output['originalEntryState']=json.loads((local/'state.json').read_text())
  if (local/'stderr.log').is_file():output['originalStderrTail']=(local/'stderr.log').read_text(errors='replace')[-6000:]
  if (BASE/'anchor026/result.json').is_file():output['workerResult']=json.loads((BASE/'anchor026/result.json').read_text())
  output['directoryFiles']=[{'name':p.name,'bytes':p.stat().st_size} for p in D.iterdir() if p.is_file() and not p.is_symlink()]
  key=(BASE/'config/api-key').read_text().strip();output['inventory']={}
  for state in ('running','paused'):
   conn=http.client.HTTPConnection('127.0.0.1',18080,timeout=20)
   try:
    conn.request('GET','/v2/sandboxes?limit=100&state='+state,headers={'X-API-Key':key});response=conn.getresponse();raw=response.read(1024**2)
    output['inventory'][state]={'status':response.status,'count':len(json.loads(raw)) if response.status==200 else None}
   finally:conn.close()
  text=json.dumps(output,separators=(',',':')).replace(key,'[REDACTED_API_KEY]')
  assert len(text.encode())<700000,'Metadata still too large; preserve original'
 else:
  index=int(mode);a=result.get('archive') if result else None
  output={'action':'READONLY_EXISTING026_ARCHIVE_CHUNK','index':index,'chunkSize':SIZE,'archiveAvailable':a is not None}
  if a:
   blob=base64.b64decode(a['base64'],validate=True);assert len(blob)<1200000 and hashlib.sha256(blob).hexdigest()==a['sha256']
   part=blob[index*SIZE:(index+1)*SIZE]
   output.update(totalBytes=len(blob),totalSha256=a['sha256'],partBytes=len(part),partSha256=hashlib.sha256(part).hexdigest(),base64=base64.b64encode(part).decode())
  text=json.dumps(output,separators=(',',':'));assert len(text.encode())<700000
 print(text,flush=True)
if __name__=='__main__':main()
