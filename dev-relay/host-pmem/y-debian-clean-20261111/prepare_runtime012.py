"""Resume verified device repair; tolerate unloaded inactive proxy units."""
import ast
from pathlib import Path
H=Path(__file__).resolve().parent
s=(H/'Y_start_runtime011.py').read_text(encoding='utf-8')
a=s.index("    stopped=json.loads(");b=s.index("    assert previous['sdk']",a)
s=s[:a]+'''    stopped=json.loads((BASE/'deployment011/result.json').read_text())
    assert stopped['unitsCreated']==[] and 'not loaded' in stopped['error']
    assert stopped['control_mount_diagnostic']['old_nodev'] and not stopped['control_mount_diagnostic']['dev_nodev']
    assert stopped['private_device_probe']['code']==0
'''+s[b:]
s=s.replace("output=BASE/'deployment011'","output=BASE/'deployment012'")
a=s.index("        assert not device_dir.exists()");b=s.index("        assert not os.statvfs(private)",a)
s=s[:a]+'''        assert device_dir.resolve()==device_dir
        directory=device_dir.lstat()
        assert stat.S_ISDIR(directory.st_mode) and directory.st_uid==0 and stat.S_IMODE(directory.st_mode)==0o711
        private=device_dir/'ublk-control';node=private.lstat()
        assert stat.S_ISCHR(node.st_mode) and node.st_uid==user.pw_uid and node.st_gid==user.pw_gid
        assert stat.S_IMODE(node.st_mode)==0o600 and node.st_rdev==original_control.st_rdev
'''+s[b:]
s=s.replace("    def root_file(path,raw,mode=0o600):\n        assert",'''    def root_file(path,raw,mode=0o600):
        if path.exists():
            st=path.lstat()
            assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==mode
            assert path.read_bytes()==(raw.encode() if isinstance(raw,str) else raw),'Existing root file differs: '+str(path)
            return
        assert''')
old="        checked(['systemctl','daemon-reload']);checked(['systemctl','reset-failed',AUTH_SERVICE,AUTH_SOCKET])"
new="""        checked(['systemctl','daemon-reload'])
        reset_failed_proxies(command,checked,(AUTH_SERVICE,AUTH_SOCKET))"""
assert old in s;s=s.replace(old,new)
function='''def reset_failed_proxies(command,checked,names):
    for name in names:
        row=command(['systemctl','show',name,'-p','ActiveState','--value'])
        state=row['stdout'].strip()
        assert row['code'] in (0,4) and state in ('inactive','failed'),'Unexpected proxy state: '+name
        if state=='failed':checked(['systemctl','reset-failed',name])

'''
s=s.replace('def main():',function+'def main():',1)
ast.parse(s,feature_version=(3,11));(H/'Y_start_runtime012.py').write_bytes(s.encode())
print('Runtime012 generated: reuse verified control inode; reset only failed proxy units')
