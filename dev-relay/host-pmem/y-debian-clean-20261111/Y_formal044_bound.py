"""Six consecutive formal rounds, archived G6 client, no diagnostic instrumentation."""
import base64,fcntl,gzip,hashlib,http.client,importlib.util,json,os,pathlib,signal,subprocess,time,uuid
P=pathlib.Path;B=P('/home/jwk/aenv-y-clean-20261111');W=B/'formal-six-20261116-044';U='jwk-aenv-y-clean-20261111.service'
BASELINE={'data': 'H4sIAAAAAAACCp1ZbXPbNhL+rl/B5gvIlqIpWZYdKeyMHTttpq7tsZ00GZ+HA5GghIoieQRlWZfzf7/dBUhRtpz22s5YBLBYLPbl2V3kzZs310JVeSmsaiasB1HKRIrY+mqVy6ySC+HifIYjIpjkyyyG9Szv8iya5aUVSz7NciWV9+bNm45cFHlZWROuxHDgTv8jC3fG1SyVE3dWVYUXpVJklavJYNZbVjJ1/1R55ubKLXhFpEpOM566ajkpyjwSSrkoSucqMATeFfyOT4Irm+3N8oXY+3M13+Mie+iuu1EqeNbt+/1hD/5jzvg0ONljpb4kCB13jcSiJhp2/UGPjT8FDNh0d7LxlCgfZCRY5+r4/W/BRZ6JTicWCdx+Cpztkq+cUSmqZZlZ5r6emvH+wZCWvJl4NJQObVuVshI23salrR2LKziiAr1WFk574lGqStmOBRJvZqUK1XqRymxuO+MkDnLl5YXINCcYXIZ/XF9enH/9L32/vz47vtWfZ1/en+uvi8sPl+fnl3+4fj70fadjrWQ1s2ApiYlVErtsNWFwsLKSUeJpUVFKklzxByP4A0+Xwhm1roJm9OLlolA2LboSfCWrgr7jiSzKY2E7P03YvzKmWcWC5mD7AjUQ84oH6DEeLiwKMJmytSN5k+GgRX3HkOyEltg9CiJhswhuSxDIGRtVpnAZ5OkEgd40WVdCsXvSqLHG1ro2GLsf4+kyFbTqsneFzDIRd01A/MxcJh5FBJ5lDI5kdCHyGVuUZV7ihUgHQbUuhJnzwjDjCxGGP7GRxX5SVWkWOlYCkYRrlswsm/16e3sVXl1ffvkKh+HgphlhFIUQFY9rM1DN6Pj8vCHjaWrmURJLiQiERXcB75YlmGkqKhsPhLMtmRiCkRaZ/nqlKFIeCVsvueyuFDGPKgh+YnwPVrSqct1ib0OgRXmWyOkeL2R3LuB0YMPjsBKP4Poe3FgW9j85EvhZwI8OFY+RKCrr8uYMlTcqwN4dy9iC+NyN9n3fvyeboANBvIhQVbxaQkCBvEWwQRYPzGqD7dcKfCCqUtCdmuUr5n5yWbeA0e9cZlcfT5kZHkeVfBA3wEzUU5/A3cANI16ACCLMl1WxrMgZXby3+QLXgZWgjyFX5qsgllFlo2SeKlJZ2Sxgbs8hR8BZdIQCFBbDJk2BswgIoDqgxXWcQS9Uy7QKvrFlJis2At7gGIKn1WzNRh94qsQTXFnGgcwAqPIVmb51LZ85IBJwLTytRIyzHwLfAkka8va1nR8CxmnMtmhID7gIMEorcOi7fg2LWswOOk9EwI0fzMUgALpN2OK0h8YifwmXIHjQ8/2+ASob1/cwAsG3CLBY2aDVRGa8XAc1AicQxKGJ9MSt43sbjY1cgA6098ZgQKCH9aEbxzYo4PsHXpUv0h1CaMJ/JoTe2wihh2OI2eDbkwYJhCoCCaMHHc51nBHEoeLIpQBrfR3/c1eJwn0goPMKXlayknkGBAFrorEgYJwT8wk7Prv4HJ5f/hJ+uLz+/fiWua2pm6vji/Ds89nF7Q3OX3+6ucV5OArEuZt7Bqqd++Ch+d7cMc2nU5lN4XpA3cGo/tvAAcicZUGrkPAQHN/DpIjoQqzXP/R8+L8HwXTkH/lN3PUODFwhC+D97yWqnv1yBleDIoLihbnwG4tSQTB96R5ffez+BpKMQJwnCLOAdoKnw0WKPFNwqXFJUto9vz+oA/HOBN8N4Q3csvQ09ID9wKfS1IgQpbna0ksds7XvBQE7PNwf+uLtYHI0jMQkOYi53xv4/n6/NxwMfJGI4dFkMBgI/yAaHPBB7+1A7O/3ov1h/8jng6MjRiY1DhmweCj8t71ekvj9g6PY70dCvD3g8RHnw74/4UfD/bf9Aw4aSHrx4eEgOoz2o9h/e+BPkv5BP+lpdruvSW7T93237w900QLWNdjxzJUg4TJMsYAhbJty40lAwqdgYHT9FS8z1tRBL9m23dFpMoHBG8wBAHyQZ5dFFUYzmcY2/cW4AL+nb0sqC2s6BC2a8Io8TRFrFZ2JawbHOoZAiSwOdZ1q6x/v5uMvHy9uazcjqhWHMKxdcJ/KLZO9WhnoVq+fPRYS8h2Gq94MQi/AEyrykteYkl//NVO9cy7xVuNdbHxdky0gLVCObLKKeCygKViALdiIfQ1NIR2COcKm9Mf62TU1NsdAvFlGKIXJPy4zlJWMnq/U+fnXrYzV3nEtIiELOB2t4LIvEO4VFQUNLcTXVIB0UDImqZzOKvak70iF+hhqCVBiHBB1U7OYdAMlEXgTZBkbfE4PhBn5YxgvF1zNbT/3Dw+bFHUCUa/yFAphoDohzzzZlbIanz19Wc6fbtXyIM+pt5jHsrQXAJeBnx+CszSSYwUBJEb3gcFUbEXu6s6G3Tvjjc62STbzSKUL9tOmJ/IKKB7Nd2t1s4kINkNHS0IY0LJrviwj0WSuur7e7GrgkZdgmwcR+/tHl6WcIiY227S836HYcImh3CJfg23sWiRLJTTAWqZXI3VBqsMo59naysQKNJ91J9CLzBa8nEMvk8WT/BGKy0LwUo0tkxbISBAZkKUsVKO1hB08m4rYY1jtFiIKtjtYD+fCpMwXIeX7NI+4TkhGsRQh2zp3xmDqZSqes9KzmhmytfGPM8a/XppjfvKw/wg1na1/2kbR4QBaqWPV1CxsjMlqHegdnlndeILWpqttMIE+PyWvqtm2iSCrIas6IGigUZk+GSEn1b3sWh9utbZD96WDgJ4b1no7a91gB5LcUxA0wtSwcSIScv7gRZ2/kW33jlbCddmJWbRMcWIKAvMeom1pJRxMG7Ndmt74OcQ9YeMMRuFiwQuk10XkdlCZ0h4ObGrIR1ND6iX35QbIYq9tgCVENZ062v3NFZHesb2lKvegstgr1tUsz/axe/mIf050Ef4i5J17mI9l1mZ2evb54tP5uaslDIyg+vhA/ziNFNsZ5rCPiPYSOM4eZfUeggzLXdq1aUJaIA5M6X3ge0psV8AvHgHeBVik/fhj32WnzX6jaUqfIlb6dQsNFgsVQcUJTlif3u7LkGFd2FIDrzDWqHVlzlazRibBhKO7XHogwRhW1PmRqkzq/owEuqGFeq2SGSE+YpdUMgNHy6Av1q8q2DnqRKK7Zoq7VprG4ulrmOWhfqFrpen9IzZqXY2270TzOucCkDfkO2y3Cc5Jnqf2hla/sTRDLaIy1NhuWs+ic6c/QA+6zaddj23ZEVVWQskmShOl1oTC3BSDCOQbLjsjGAvSFHI/Q5V/56aWgCLCaq2E+sAQnSLERyvIPoQSxrAILWf0iRgCwUoeM2rJQBPo/q3nI92UmfzfeBH+WkWwjdh7mo+HzsWIgnp5KC8wFdn4LrkLwFu+WLR7rbZT2uaNxd14p2PeW+pexlSmu0vsTWX6ihaavhfJ3+P9l8XZq+r4XnpodPQc74+TCp9ndiSI55S/bhow9OZXGLXyRltVf3HBmsn7mYjmZ3/L4NtPgrtBz30tQWxcBVns8gqas0q+Copt5DTupASwSzh82gzLmfQ8nyrmfnty7pDlPbQG+kF1hBiL78PN48ao9Sr+pM+Bw3GXB12TwmwIaNCSVveVfDXaAQeonVsIsUZfpqCgBTzirguZxR/dv4rI2qXRN+jxWkdPEzGuHvwfttS/N8DrFUOiUltv4ZoeX2A4OC3KZoPhXGhYHGN2o8Hmldz5ORgO8FIoFEAYNGXQBXybGxEITuf6rVC/17Thf2cjtqsFe9l87Wq7tjquutdyDWi5u4Dbfa0tcL9T2WtHqe/qLQt80beTZZr+DnMIrtdm7TL7GpiCpW1Hx10YwhN0y+CFTpt1fWKwcdINjaOF0G1WS9nbFfK3J3r7J2mew6o2EtX4L62kC92XSqTf23UhtPFIZ8fxQipF57GmZTnPo/m1AG9TYAznafzC07RQr/paqyrauvc7crdxUdIbMV+5SbpUM/0PKh1w0PofLqCyCEN8IwhDNtJvBZ3/ATVtJG5DHAAA', 'sha256': 'ea6feca99b513c53f8a07a34fabe3ba48c6deb2a27f26a11e139a646a0861a28'}
def sha(b):return hashlib.sha256(b).hexdigest()
def save(p,x):p.write_text(json.dumps(x,indent=2)+'\n')
def owned_dir(p):p.mkdir(mode=0o700);os.chown(p,1002,1002)
def main():
 result={'experiment':'Y_FORMAL_REPEAT044','success':False,'baselineHealthy':False,'completedRounds':0,'XContacted':False,'anchor':False,'perf':False,'detailedLogging':False,'poolConfigurationChanged':False,'stage':'preflight'};child=None;lock=None;baseline=None;key=None;tags=[];created=False
 def api(method,path,body=None):
  c=http.client.HTTPConnection('127.0.0.1',18080,timeout=15)
  try:
   c.request(method,path,body=json.dumps(body) if body is not None else None,headers={'X-API-Key':key,'Content-Type':'application/json'});r=c.getresponse();raw=r.read(4*1024**2);assert r.status in (200,201,204,404),'API status '+str(r.status);return json.loads(raw) if raw and r.status!=404 else None
  finally:c.close()
 def inventory():return sum((api('GET','/v2/sandboxes?limit=100&state='+s) for s in ('running','paused')),[])
 def pool():
  previous=None;stable=0;end=time.monotonic()+180
  while time.monotonic()<end:
   current={}
   for p in P('/proc').iterdir():
    if not p.name.isdigit():continue
    try:
     if p.stat().st_uid==1002 and (p/'comm').read_text().strip()=='firecracker' and P(os.readlink(p/'cwd')).is_relative_to(B/'fc'):current[p.name]=(p/'stat').read_text().rsplit(')',1)[1].split()[19]
    except OSError:continue
   stable=stable+1 if current==previous and 300<=len(current)<=1000 else 0;previous=current
   if stable>=5:
    for n,start in current.items():
     p=P('/proc',n);assert (p/'stat').read_text().rsplit(')',1)[1].split()[19]==start and '/system.slice/'+U in (p/'cgroup').read_text()
     assert next(x for x in (p/'limits').read_text().splitlines() if x.startswith('Max open files')).split()[3:5]==['1048576','1048576']
    return {'count':len(current),'stableSamples':5,'nofile':1048576}
   time.sleep(1)
  raise RuntimeError('Natural pool not stable')
 def resources():
  mem={x.split(':',1)[0]:x.split(':',1)[1].strip() for x in P('/proc/meminfo').read_text().splitlines()};psi={s:P('/proc/pressure',s).read_text() for s in ('cpu','io','memory')}
  return {'memAvailableBytes':int(mem['MemAvailable'].split()[0])*1024,'loadavg':P('/proc/loadavg').read_text().strip(),'psi':psi,'monotonicNs':time.monotonic_ns()}
 def launch(folder,rounds,barrier,pid):
  owned_dir(folder);tag='formal044-'+uuid.uuid4().hex;tags.append(tag);save(W/'owned-tags.json',tags)
  args=['nsenter','--target',str(pid),'--net','--mount','--','setpriv','--reuid=1002','--regid=1002','--clear-groups','--inh-caps=-all','--ambient-caps=-all','--bounding-set=-all','--no-new-privs',str(W/'lifecycle-go'),'-output',str(folder),'-template',result['templateId'],'-run-id',tag,'-rounds',str(rounds),'-barrier='+str(barrier).lower()]
  env={'PATH':'/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin','HOME':'/home/jwk','USER':'jwk','LOGNAME':'jwk','LANG':'C.UTF-8','NO_PROXY':'localhost,127.0.0.1','E2B_API_URL':'http://127.0.0.1:18080','E2B_API_KEY':key}
  f=(folder/'client.log').open('xb');p=subprocess.Popen(args,env=env,stdin=subprocess.DEVNULL,stdout=f,stderr=subprocess.STDOUT,start_new_session=True);f.close();return p
 try:
  assert os.getuid()==os.geteuid()==0;os.umask(0o077);assert P('/proc/sys/kernel/random/boot_id').read_text().strip()=='d005bda4-518d-4766-b704-259df7bae4f9'
  assert B.resolve()==B and B.stat().st_uid==1002 and not W.exists();owned_dir(W);created=True
  raw=gzip.decompress(base64.b64decode(BASELINE['data']));assert sha(raw)==BASELINE['sha256'];code=W/'baseline-check.py';code.write_bytes(raw);code.chmod(0o600)
  spec=importlib.util.spec_from_file_location('baseline',code);baseline=importlib.util.module_from_spec(spec);spec.loader.exec_module(baseline)
  result['baselineBefore']=baseline.baseline_status();assert result['baselineBefore']['healthy'],'Existing baseline is not compact/warn or not healthy'
  lockpath=B/'scripts/.run.lock';assert lockpath.resolve()==lockpath and lockpath.is_file() and lockpath.stat().st_uid==1002
  lock=os.open(lockpath,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  key=(B/'config/api-key').read_text().strip();assert inventory()==[],'Foreign sandboxes preserved'
  result['resourcesBefore']=resources();assert result['resourcesBefore']['memAvailableBytes']>=64*1024**3,'Memory admission below64GiB'
  for kind in ('cpu','io'):
   fields=dict(x.split('=',1) for x in result['resourcesBefore']['psi'][kind].splitlines()[0].split()[1:]);assert float(fields['avg10'])<5,'Host pressure is too high for comparable formal test'
  result['neighborThresholds']=[P('/proc/sys/net/ipv4/neigh/default/gc_thresh'+str(i)).read_text().strip() for i in (1,2,3)];assert result['neighborThresholds']==['16384','32768','65536']
  binary_path=B/'g7-20261112-031/lifecycle-go';assert binary_path.resolve()==binary_path and binary_path.stat().st_uid==1002;binary=binary_path.read_bytes()
  assert sha(binary)=='d6d9378d833523967d0beefec4c70205027fe4b31c3057408d364bc180fdf653' and len(binary)==9991485 and binary[:4]==b'\x7fELF' and int.from_bytes(binary[18:20],'little')==62
  (W/'lifecycle-go').write_bytes(binary);(W/'lifecycle-go').chmod(0o700);os.chown(W/'lifecycle-go',1002,1002);result['clientSha256']=sha(binary)
  result['templateId']=json.loads((B/'wikidata017/result.json').read_text())['templateId'];template=next(x for x in api('GET','/templates') if x['templateID']==result['templateId']);assert template['buildStatus']=='ready' and template['cpuCount']==2 and template['memoryMB']==4096
  result['stage']='formal_configuration_restart';assert inventory()==[];subprocess.run(['systemctl','restart',U],check=True,timeout=120);end=time.monotonic()+180
  while True:
   try:
    status=baseline.baseline_status();assert status['healthy'];pid=int(status['unit']['MainPID']);break
   except (OSError,AssertionError,ValueError,http.client.HTTPException):assert time.monotonic()<end;time.sleep(.5)
  result['logging']=status['logging'];assert inventory()==[];result['initialPool']=pool()
  result['stage']='full100_prewarm';child=launch(W/'prewarm100',1,False,pid);assert child.wait(timeout=900)==0;child=None
  assert json.loads((W/'prewarm100/result/summary.json').read_text())['valid'] and inventory()==[];result['afterPrewarmPool']=pool()
  result['stage']='singleton_warmup';child=launch(W/'formal',6,True,pid);end=time.monotonic()+120
  while not (W/'formal/warmup-ready.json').exists():assert child.poll() is None and time.monotonic()<end;time.sleep(.05)
  assert inventory()==[];result['startPool']=pool();result['resourcesAtStart']=resources();save(W/'manifest.json',{k:v for k,v in result.items() if k not in ('error',)})
  result['stage']='six_consecutive_formal_rounds';(W/'formal/CONTINUE').write_text('start');os.chown(W/'formal/CONTINUE',1002,1002)
  exit_code=child.wait(timeout=1800);child=None;result['clientExitCode']=exit_code
  summary=json.loads((W/'formal/result/summary.json').read_text());result['summary']=summary;result['completedRounds']=len(summary.get('rounds',[]));result['phaseWindows']=json.loads((W/'formal/result/phase-windows.json').read_text())
  raw=(W/'formal/result/operations.jsonl').read_bytes();assert len(raw)<=2*1024**2;result['operationsBytes']=len(raw);result['operationsSha256']=sha(raw);result['operationsGzipBase64']=base64.b64encode(gzip.compress(raw,mtime=0)).decode()
  assert exit_code==0 and summary['valid'] and summary['rounds_succeeded']==6 and not summary['remaining_sandboxes'] and inventory()==[]
  assert all(summary[p]['succeeded']==600 and summary[p]['failed']==0 for p in ('create','pause','resume','delete'))
  result['resourcesAfter']=resources();result['stage']='complete';result['success']=True
 except BaseException as error:result['error']=baseline.clean(error) if baseline else type(error).__name__+': '+str(error)[:1000]
 finally:
  if child is not None and child.poll() is None:
   try:
    os.killpg(child.pid,signal.SIGTERM)
    try:child.wait(timeout=25)
    except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=10)
   except ProcessLookupError:pass
  if key:
   try:
    for row in inventory():
     if row.get('metadata',{}).get('lifecycle_benchmark_run') in tags:
      sid=row['sandboxID'];check=api('GET','/sandboxes/'+sid)
      if check and check.get('metadata',{}).get('lifecycle_benchmark_run') in tags and check.get('templateID')==result['templateId']:api('DELETE','/sandboxes/'+sid)
    result['finalInventoryCount']=len(inventory())
   except BaseException as error:result['cleanupError']=baseline.clean(error);result['success']=False
  if baseline:
   try:result['baselineAfter']=baseline.baseline_status();result['baselineHealthy']=result['baselineAfter']['healthy']
   except BaseException as error:result['baselineError']=type(error).__name__
  result['success']=bool(result['success'] and result['baselineHealthy'] and result.get('finalInventoryCount')==0)
  if lock is not None:fcntl.flock(lock,fcntl.LOCK_UN);os.close(lock)
  if created:
   p=W/'formal/result/operations.jsonl'
   if p.is_file() and 'operationsGzipBase64' not in result:
    raw=p.read_bytes()
    if len(raw)<=2*1024**2:result.update(operationsBytes=len(raw),operationsSha256=sha(raw),operationsGzipBase64=base64.b64encode(gzip.compress(raw,mtime=0)).decode())
   save(W/'result.json',result)
  raw=json.dumps(result,separators=(',',':'));assert len(raw.encode())<256*1024;print(raw,flush=True)
if __name__=='__main__':main()
