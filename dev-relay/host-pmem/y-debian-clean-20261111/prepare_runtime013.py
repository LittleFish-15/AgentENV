"""Populate missing public OS identity in the runtime's private /etc mirror."""
import ast
from pathlib import Path
H=Path(__file__).resolve().parent
s=(H/'Y_start_runtime012.py').read_text(encoding='utf-8')
a=s.index("    stopped=json.loads(");b=s.index("    assert previous['sdk']",a)
s=s[:a]+'''    stopped=json.loads((BASE/'deployment012/result.json').read_text())
    assert stopped['error']=='Runtime did not reach Rust health204'
    assert 'Error: read /etc/os-release' in stopped['diagnostics'][str(BASE/'logs/server.log')]
    assert stopped['proxy_probe']['code']==0 and stopped['private_device_probe']['code']==0
    assert all(row['code']==0 for row in stopped['failure_cleanup'].values())
'''+s[b:]
s=s.replace("output=BASE/'deployment012'","output=BASE/'deployment013'")
needle="        assert (private_etc/'passwd').read_bytes()==P('/etc/passwd').read_bytes()"
assert needle in s
s=s.replace(needle,needle+'''
        os_release=P('/etc/os-release')
        public=os_release.stat()
        assert stat.S_ISREG(public.st_mode) and public.st_mode & 0o004 and public.st_size<=65536
        raw=os_release.read_bytes()
        assert b'ID=debian' in raw or b'ID="debian"' in raw,'Unexpected OS release preserved'
        own_file(private_etc/'os-release',raw)
        # Dereference the host symlink, so the private mirror needs no outside target.
        assert not (private_etc/'os-release').is_symlink()
        result['private_os_release']={'copiedPublicBytes':len(raw),'sha256':digest(private_etc/'os-release'),'regularFile':True}
''')
# Log a per-attempt suffix, so historical errors are not mistaken for the latest error.
needle="        result['runtime_launch']=launch"
s=s.replace(needle,"        result['server_log_offset']=(BASE/'logs/server.log').stat().st_size if (BASE/'logs/server.log').exists() else 0\n"+needle)
needle="with path.open('rb') as f:f.seek(max(0,path.stat().st_size-22000));result['diagnostics'][str(path)]=f.read().decode(errors='replace')"
replacement="with path.open('rb') as f:f.seek(max(result.get('server_log_offset',0) if path==BASE/'logs/server.log' else 0,path.stat().st_size-22000));result['diagnostics'][str(path)]=f.read().decode(errors='replace')"
assert needle in s;s=s.replace(needle,replacement)
ast.parse(s,feature_version=(3,11));(H/'Y_start_runtime013.py').write_bytes(s.encode())
print('Runtime013 generated: copy public Debian os-release as a private regular file; retain runtime isolation')
