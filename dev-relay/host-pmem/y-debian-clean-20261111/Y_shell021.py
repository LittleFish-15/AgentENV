"""Configure only jwk interactive Bash and verify prompt, arrows, history, ll."""
import hashlib,json,os,pathlib,pty,pwd,select,shutil,stat,subprocess,time
P=pathlib.Path;BASE=P('/home/jwk/aenv-y-clean-20261111')
BEGIN='# BEGIN JWK_INTERACTIVE_SHELL021';END='# END JWK_INTERACTIVE_SHELL021'
RC=r'''
# BEGIN JWK_INTERACTIVE_SHELL021
case $- in
  *i*)
    PS1='\u@\h:\w\$ '
    alias ll='ls -l'
    set -o emacs
    set -o history
    bind '"\e[A": previous-history'
    bind '"\e[B": next-history'
    bind '"\e[C": forward-char'
    bind '"\e[D": backward-char'
    bind '"\eOA": previous-history'
    bind '"\eOB": next-history'
    bind '"\eOC": forward-char'
    bind '"\eOD": backward-char'
    _JWK_INTERACTIVE_SHELL021_LOADED=1
    ;;
esac
# END JWK_INTERACTIVE_SHELL021
'''
PROFILE=r'''
# BEGIN JWK_INTERACTIVE_PROFILE021
if [ -n "${BASH_VERSION-}" ] && [ "${_JWK_INTERACTIVE_SHELL021_LOADED-}" != 1 ]; then
    case $- in *i*) [ ! -r "$HOME/.bashrc" ] || . "$HOME/.bashrc" ;; esac
fi
# END JWK_INTERACTIVE_PROFILE021
'''
def main():
 assert os.getuid()==os.geteuid()==0;os.umask(0o077)
 user=pwd.getpwnam('jwk');assert user.pw_uid==user.pw_gid==1002
 home=P(user.pw_dir);assert home==P('/home/jwk') and home.resolve()==home
 bash=P('/bin/bash');assert bash.is_file() and os.access(bash,os.X_OK)
 assert str(bash) in P('/etc/shells').read_text().splitlines(),'Bash is not an approved login shell'
 folder=BASE/'shell-setup021';assert not folder.exists();folder.mkdir(mode=0o700);os.chown(folder,1002,1002)
 result={'action':'JWK_INTERACTIVE_SHELL_SETUP','before':{'shell':user.pw_shell,'uid':user.pw_uid,'gid':user.pw_gid,'home':user.pw_dir},'backups':[],'files':{},'serviceChanged':False}
 def update(path,block,begin,end):
  assert path.parent==home and not path.is_symlink(),'Linked shell configuration preserved: '+str(path)
  mode=0o600;raw=b''
  if path.exists():
   st=path.lstat();assert stat.S_ISREG(st.st_mode) and st.st_uid in (0,1002) and st.st_size<1024**2
   raw=path.read_bytes();mode=stat.S_IMODE(st.st_mode)|0o200
   backup=folder/(path.name+'.before');backup.write_bytes(raw);backup.chmod(0o600);os.chown(backup,1002,1002);result['backups'].append(str(backup))
  text=raw.decode('utf-8');assert begin not in text and end not in text,'Existing setup block preserved'
  final=text+('' if not text or text.endswith('\n') else '\n')+block
  temp=home/(path.name+'.shell021.tmp');assert not temp.exists() and not temp.is_symlink()
  temp.write_text(final);temp.chmod(mode);os.chown(temp,1002,1002)
  check=subprocess.run([str(bash),'-n',str(temp)],capture_output=True,text=True,timeout=10)
  assert check.returncode==0,'Shell configuration syntax check failed'
  temp.replace(path);result['files'][str(path)]={'sha256':hashlib.sha256(final.encode()).hexdigest(),'uid':1002,'mode':oct(mode)}
 try:
  update(home/'.bashrc',RC,BEGIN,END)
  login=next((home/name for name in ('.bash_profile','.bash_login','.profile') if (home/name).exists() or (home/name).is_symlink()),home/'.profile')
  update(login,PROFILE,'# BEGIN JWK_INTERACTIVE_PROFILE021','# END JWK_INTERACTIVE_PROFILE021')
  if P(user.pw_shell).resolve()!=bash.resolve():
   subprocess.run([shutil.which('usermod') or '/usr/sbin/usermod','--shell',str(bash),'jwk'],check=True,capture_output=True,text=True,timeout=20)
  assert P(pwd.getpwnam('jwk').pw_shell).resolve()==bash.resolve()
  env={'PATH':'/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin','HOME':str(home),'USER':'jwk','LOGNAME':'jwk','LANG':'C.UTF-8','TERM':'xterm-256color','HISTFILE':'/dev/null'}
  def probe(login=False):
   code="printf '__JWK_VERSION021__=%s\\n' \"$BASH_VERSION\"; printf '__JWK_PROMPT021__=%s\\n' \"$PS1\"; printf '__JWK_ALIAS021__=%s\\n' \"$(alias ll)\"; printf '__JWK_EMACS021__=%s\\n' \"$(set -o | awk '$1==\"emacs\" {print $2}')\""
   command=['runuser','-u','jwk','--',str(bash),*(['--login'] if login else []),'-i','-c',code]
   r=subprocess.run(command,env=env,cwd=home,capture_output=True,text=True,timeout=20)
   markers={line.split('=',1)[0]:line.split('=',1)[1] for line in r.stdout.splitlines() if line.startswith('__JWK_') and '=' in line}
   assert r.returncode==0 and markers.get('__JWK_ALIAS021__')=="alias ll='ls -l'"
   assert markers.get('__JWK_PROMPT021__')==r'\u@\h:\w\$ ' and markers.get('__JWK_EMACS021__')=='on'
   return {'bashVersion':markers['__JWK_VERSION021__'],'prompt':markers['__JWK_PROMPT021__'],'ll':'ls -l','emacs':'on'}
  result['interactive']=probe();result['loginInteractive']=probe(True)
  master,slave=pty.openpty()
  child=subprocess.Popen(['runuser','-u','jwk','--',str(bash),'-i'],env=env,cwd=home,stdin=slave,stdout=slave,stderr=slave,start_new_session=True);os.close(slave)
  data=bytearray()
  def wait_for(value,count=1,seconds=8):
   deadline=time.monotonic()+seconds
   while bytes(data).count(value)<count and time.monotonic()<deadline:
    if select.select([master],[],[],.2)[0]:
     try:chunk=os.read(master,65536)
     except OSError:break
     if not chunk:break
     data.extend(chunk)
   assert bytes(data).count(value)>=count,'Interactive key test did not produce expected output'
  try:
   wait_for(b'$ ')
   os.write(master,b'HISTFILE=/dev/null\n')
   # Left then insert b before c; forward-char then end-of-line executes abc.
   os.write(master,b"printf '__JWK_EDIT021__=%s\\n' ac\x1b[Db\x1b[C\n")
   wait_for(b'__JWK_EDIT021__=abc\r\n')
   os.write(master,b"printf '__JWK_HISTORY021__=ok\\n'\n")
   wait_for(b'__JWK_HISTORY021__=ok\r\n')
   os.write(master,b'\x1b[A\n');wait_for(b'__JWK_HISTORY021__=ok\r\n',count=2)
   os.write(master,b'exit\n');child.wait(timeout=10)
   result['ptyKeys']={'leftRightEditing':True,'upArrowHistory':True}
  finally:
   if child.poll() is None:child.terminate();child.wait(timeout=5)
   os.close(master)
  result.update(status='CONFIGURED_AND_VERIFIED',afterShell=pwd.getpwnam('jwk').pw_shell,reenterCommand='su - jwk')
 except BaseException as error:result.update(status='FAILED_PRESERVE_BACKUPS',errorType=type(error).__name__,error=str(error)[:1000]);raise
 finally:
  path=folder/'result.json';path.write_text(json.dumps(result,indent=2)+'\n');os.chown(path,1002,1002)
  print(json.dumps(result),flush=True)
if __name__=='__main__':main()
