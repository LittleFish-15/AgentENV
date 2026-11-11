"""Read configured pool limits and FC states for the dedicated jwk unit."""
import pathlib,os,json,tomllib,subprocess,collections,socket,http.client
R=pathlib.Path('/home/jwk/aenv-y-clean-20261111');UNIT='jwk-aenv-y-clean-20261111.service'
c=tomllib.loads((R/'config/runtime005.toml').read_text())
values=dict(x.split('=',1) for x in subprocess.check_output(['systemctl','show',UNIT,'-p','MainPID','-p','ControlGroup','-p','ActiveState','-p','User'],text=True).splitlines())
assert values['User']=='jwk' and values['ControlGroup'].endswith('/'+UNIT)
group=pathlib.Path('/sys/fs/cgroup')/values['ControlGroup'].lstrip('/')
states=collections.Counter();fc=0;errors=[]
for pid in (group/'cgroup.procs').read_text().split():
 p=pathlib.Path('/proc')/pid
 try:
  if (p/'comm').read_text().strip()!='firecracker':continue
  assert p.stat().st_uid==1002;fc+=1
  args=(p/'cmdline').read_bytes().decode().strip('\0').split('\0')
  name=args[args.index('--api-sock')+1]
  path=name if name.startswith('/') else str(p/'cwd'/name)
  sock=socket.socket(socket.AF_UNIX);sock.settimeout(.5)
  conn=http.client.HTTPConnection('localhost',timeout=.5);conn.sock=sock
  try:
   sock.connect(path);conn.request('GET','/');response=conn.getresponse();body=response.read()
   assert response.status==200,response.status
   state=json.loads(body)['state'];states[state]+=1
  finally:conn.close()
 except FileNotFoundError:states['exited_during_check']+=1
 except Exception as e:
  states['unverified']+=1
  if len(errors)<3:errors.append({'pid':pid,'error':type(e).__name__+': '+str(e)})
print(json.dumps({'unit':UNIT,'active':values['ActiveState'],'server_pid':int(values['MainPID']),'config_path':str(R/'config/runtime005.toml'),'configured_pool':c['pool'],'fc_process_count':fc,'fc_states':dict(states),'errors':errors},indent=2))
