"""Resume deployment010 with a device-enabled private control inode."""
import ast,hashlib,json
from pathlib import Path
H=Path(__file__).resolve().parent
s=(H/'Y_start_runtime010.py').read_text(encoding='utf-8')
a=s.index("    stopped=json.loads(")
b=s.index("    assert previous['sdk']",a)
s=s[:a]+'''    stopped=json.loads((BASE/'deployment010/result.json').read_text())
    assert stopped['error']=='Runtime did not reach Rust health204'
    assert stopped['proxy_probe']['code']==0 and stopped['proxy_isolation']['capabilities']==0
    assert "Permission denied: '/dev/ublk-control'" in stopped['diagnostics'][str(BASE/'logs/launcher.log')]
    assert all(row['code']==0 for row in stopped['failure_cleanup'].values())
'''+s[b:]
s=s.replace("output=BASE/'deployment010'","output=BASE/'deployment011'")
# Existing failed transient units can remain loaded: require inactive and exact ownership.
s=s.replace("        for name in (UNIT,BROKER,RELAYS):assert unit_state(name)=='not-found','Existing unit preserved: '+name",'''        for name in (UNIT,BROKER,RELAYS):
            state_row=command(['systemctl','show',name,'-p','ActiveState','--value'])['stdout'].strip()
            assert state_row in ('inactive','failed'),'Active existing unit preserved: '+name
            if unit_state(name)!='not-found':
                details=checked(['systemctl','show',name,'-p','Transient','-p','Description'])['stdout']
                assert 'Transient=yes' in details and 'Description=Independent jwk AgentENV Y' in details
                checked(['systemctl','reset-failed',name])
''')
s=s.replace("    def own_file(path,raw,mode=0o600):\n        assert",'''    def own_file(path,raw,mode=0o600):
        if path.exists():
            st=path.lstat()
            assert stat.S_ISREG(st.st_mode) and st.st_uid==user.pw_uid and stat.S_IMODE(st.st_mode)==mode
            assert path.read_bytes()==(raw.encode() if isinstance(raw,str) else raw),'Existing file differs: '+str(path)
            return
        assert''')
a=s.index("        result['control_access']=")
b=s.index("        excluded=[]",a)
s=s[:a]+'''        old_private=private
        result['control_mount_diagnostic']={'old_path':str(old_private),'old_mode':oct(stat.S_IMODE(node.st_mode)),
            'old_uid':node.st_uid,'old_nodev':bool(os.statvfs(old_private).f_flag & os.ST_NODEV),
            'dev_nodev':bool(os.statvfs('/dev').f_flag & os.ST_NODEV)}
        assert result['control_mount_diagnostic']['old_nodev'],'Cause differs from nodev; preserve and inspect'
        assert not result['control_mount_diagnostic']['dev_nodev'],'Host /dev unexpectedly nodev'
        # Create a new private inode on devtmpfs; never chmod/chown the host control inode.
        device_dir=P('/dev/jwk-aenv-y-clean-20261111-011')
        assert not device_dir.exists() and not device_dir.is_symlink()
        device_dir.mkdir(mode=0o711);os.chmod(device_dir,0o711)
        private=device_dir/'ublk-control'
        os.mknod(private,stat.S_IFCHR|0o600,original_control.st_rdev)
        os.chown(private,user.pw_uid,user.pw_gid)
        assert not os.statvfs(private).f_flag & os.ST_NODEV
        probe_device=command(['/usr/bin/python3','-I','-B','-c',
            "import os,sys;fd=os.open(sys.argv[1],os.O_RDWR|os.O_CLOEXEC);os.close(fd);print('PRIVATE_CONTROL_OPEN_OK')",private],as_user=True)
        result['private_device_probe']=probe_device
        assert probe_device['code']==0,'New private device cannot open; preserve diagnostics'
        result['control_access']='Private devtmpfs inode bound inside only the jwk runtime; host control inode unchanged'
'''+s[b:]
s=s.replace('device_broker010.py','device_broker011.py').replace('broker-config010.json','broker-config011.json')
# Keep old run.sh and supervisor: identical code, no need to overwrite them.
a=s.index("        code_dir=ROOT/'proxy-code010'")
b=s.index("        checked(['systemctl','daemon-reload'])",a)
s=s[:a]+'''        code_dir=ROOT/'proxy-code010'
        assert digest(code_dir/'auth_proxy010.py')==UNIT_PROOF['new_proxy_sha256']
        dropin=unit_root/(AUTH_SERVICE+'.d')/'10-python313-socket010.conf'
        assert digest(dropin)==UNIT_PROOF['dropin_sha256']
'''+s[b:]
s=s.replace("(ROOT/'broker-ready.json')","(ROOT/'broker-ready011.json')")
s=s.replace("        result['runtime_launch']=launch",'''        result['runtime_launch']=launch''')
s=s.replace("        assert ready,'Runtime did not reach Rust health204'",'''        assert ready,'Runtime did not reach Rust health204' ''')
broker=(H/'device_broker010.py').read_text(encoding='utf-8').replace('broker-config010.json','broker-config011.json').replace('broker-ready.json','broker-ready011.json')
proof=json.loads((H/'runtime010-unit-proof.json').read_text(encoding='utf-8'))
proof['new_proxy_sha256']=hashlib.sha256((H/'auth_proxy010.py').read_bytes()).hexdigest()
dropin='[Service]\nExecStart=\nExecStart=/usr/bin/python3 -I -B /run/jwk-aenv-y-clean-20261111/proxy-code010/auth_proxy010.py\n'
proof['dropin_sha256']=hashlib.sha256(dropin.encode()).hexdigest()
for name,body in [('Y_start_runtime011.py',s),('device_broker011.py',broker)]:
    ast.parse(body,feature_version=(3,11));(H/name).write_bytes(body.encode())
(H/'runtime011-unit-proof.json').write_text(json.dumps(proof,indent=2)+'\n',encoding='utf-8')
print('Runtime011 generated: conditional nodev repair, private devtmpfs inode, original config/binaries retained')
