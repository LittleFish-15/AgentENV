"""One Y no-anchor formal round using the archived G6 request implementation."""
from pathlib import Path
import ast,json
H=Path(__file__).resolve().parent
s=(H/'Y_g7_run033_bound.py').read_text(encoding='utf-8').replace("W=B/'g7-20261112-033'","W=B/'g6-no-anchor-20261113-036'")
s=s.replace("  for mode in ('formal','diagnostic'):","  for mode in ('formal',):")
# Reuse the already delivered exact G6-derived executable, not the new repository client.
a=s.index("  prior_attempt=json.loads(");b=s.index('  template=json.loads',a)
proof=json.loads((H/'debian-runtime031-publication.private.json').read_text())['buildProof']
install="""  proof=PROOF
  executable=B/'g7-20261112-031/lifecycle-go'
  assert executable.is_file() and not executable.is_symlink() and executable.stat().st_uid==1002 and sha(executable)==proof['binarySha256'],'Archived G6 client differs'
  binary=executable.read_bytes();assert len(binary)==proof['binaryBytes'] and binary[:4]==b'\\x7fELF' and int.from_bytes(binary[18:20],'little')==62
  assert sha(W/'lifecycle.go')==proof['sourceSha256']
  destination=W/'lifecycle-go';destination.write_bytes(binary);destination.chmod(0o700);os.chown(destination,1002,1002)
  save(W/'build-proof.json',proof)
  result.update(group='Y-no-anchor-single',formalRounds=1,G6Reference='archived formal5',G6PoolReference=600,client='archived G6 Go; UID-only source adaptation')
""".replace('PROOF',repr(proof))
s=s[:a]+install+s[b:]
s=s.replace("'group':'G7'","'group':'Y-no-anchor-single'")
start=s.index("   drop=dropdir/'29-g7-logging.conf'");end=s.index('   deadline=time.monotonic()',start)
replacement="""   drop=dropdir/'36-g6-no-anchor.conf';assert not drop.exists() and not drop.is_symlink(),'Existing036 logging task preserved'
   body='[Service]\\nExecStart=\\nExecStart=/usr/bin/python3 -I -B '+str(W/'runtime_formal.py')+' inside\\n'
   (d/'dropin-applied.conf').write_text(body)
   drop.write_text(body);drop.chmod(0o644);run(['systemctl','daemon-reload']);run(['systemctl','restart',U],120)
"""
s=s[:start]+replacement+s[end:]
assert s.count('pool(1000)')==2;s=s.replace('pool(1000)','pool()')
s=s.replace("    assert stable>=5,'FC pool not stable'","    assert stable>=5,'FC pool not stable'\n    assert 300<=len(last)<=1000,'Natural FC count outside configured range'")
s=s.replace("5 if mode=='formal' else 1","1")
s=s.replace("(500 if mode=='formal' else 100)","100")
s=s.replace("'G6ArchivedPool':600,'poolDifferenceAcceptedByUser':True","'G6ArchivedPool':600,'matchesG6Pool':startpool['count']==600,'poolPolicy':'natural stable; recorded; no forced pool manipulation'")
s=s.replace("'archiveSha256':sha(W/'evidence.tar.gz'),'error':result.get('error')","'archiveSha256':sha(W/'evidence.tar.gz'),'error':result.get('error')")
# stdout stays below the entry bound; all formal evidence can fit a single receipt.
needle="  print(json.dumps({'group':"
position=s.index(needle)
s=s[:position]+"""  archive=W/'evidence.tar.gz';blob=archive.read_bytes()
  output={'group':'Y-no-anchor-single','success':result['success'],'completedModes':list(result['modes']),'error':result.get('error'),'errorType':result.get('errorType'),'stage':result.get('stage'),'archiveBytes':len(blob),'archiveSha256':sha(archive)}
  if len(blob)<=450000:output['archiveBase64']=base64.b64encode(blob).decode()
  if 'formal' in result['modes']:output['formal']=result['modes']['formal']
  text=json.dumps(output,separators=(',',':'));assert len(text.encode())<800000
  print(text,flush=True)
if __name__=='__main__':main()
"""
ast.parse(s,feature_version=(3,11));assert len(s.encode())<256*1024
def bundle(text):return ast.literal_eval(next(n.value for n in ast.parse(text).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='BUNDLE' for t in n.targets)))
assert bundle(s)==bundle((H/'Y_g7_run033_bound.py').read_text(encoding='utf-8'))
assert "for mode in ('formal',):" in s and "launch(d,1,True)" in s and 'pool(1000)' not in s
(H/'Y_no_anchor036_bound.py').write_bytes(s.encode())
print(json.dumps({'prepared':True,'formalRounds':1,'concurrency':100,'anchor':False,'perf':False,'archivedClientBytesUnchanged':True,'bytes':len(s.encode())}))
