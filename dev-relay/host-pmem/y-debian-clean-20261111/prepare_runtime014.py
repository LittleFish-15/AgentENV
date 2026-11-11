"""Restore public command alternatives in private etc and preflight in netns."""
import ast
from pathlib import Path
H=Path(__file__).resolve().parent
s=(H/'Y_start_runtime013.py').read_text(encoding='utf-8')
a=s.index("    stopped=json.loads(");b=s.index("    assert previous['sdk']",a)
s=s[:a]+'''    stopped=json.loads((BASE/'deployment013/result.json').read_text())
    assert stopped['error']=='Runtime did not reach Rust health204'
    failure=stopped['diagnostics'][str(BASE/'logs/server.log')]
    assert 'command iptables-restore' in failure and 'command iptables-save' in failure
    assert stopped['proxy_probe']['code']==0 and stopped['private_device_probe']['code']==0
    assert all(row['code']==0 for row in stopped['failure_cleanup'].values())
'''+s[b:]
s=s.replace("output=BASE/'deployment013'","output=BASE/'deployment014'")
needle="        # Keep existing credentials and original unit files intact"
repair='''        manifest_path=source/'config/deps_manifest.toml'
        # source was reassigned to the decoded helper bundle above.
        manifest_path=BASE/'source/AgentENV/config/deps_manifest.toml'
        manifest=tomllib.loads(manifest_path.read_text())
        commands=sorted(manifest['packages']['runtime_commands'])
        assert 'iptables-restore' in commands and 'iptables-save' in commands
        alternatives=private_etc/'alternatives';own_dir(alternatives)
        command_proof=[]
        for name in commands:
            assert re.fullmatch(r'[a-zA-Z0-9_.+-]+',name)
            found=shutil.which(name,path=environment['PATH'])
            assert found,'Required host command missing: '+name
            origin=P(found);target=origin.resolve(strict=True);st=target.stat()
            assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_mode&0o005==0o005 and not st.st_mode&0o022
            assert str(target).startswith(('/usr/bin/','/usr/sbin/','/usr/local/bin/','/usr/local/sbin/','/bin/','/sbin/'))
            cursor=origin;seen=set();count=0
            while cursor.is_symlink():
                count+=1;assert count<=16 and str(cursor) not in seen;seen.add(str(cursor))
                if cursor.parent==P('/etc/alternatives'):
                    dest=alternatives/cursor.name
                    assert not dest.exists() and not dest.is_symlink(),'Existing private alternative preserved'
                    dest.symlink_to(target);os.lchown(dest,user.pw_uid,user.pw_gid)
                link=os.readlink(cursor)
                cursor=P(os.path.normpath(link if os.path.isabs(link) else str(cursor.parent/link)))
            command_proof.append({'command':name,'hostPath':str(origin),'resolved':str(target)})
        own_file(BASE/'config/runtime-command-proof014.json',json.dumps(command_proof)+'\\n')
        result['runtime_command_links']=command_proof
'''
# Remove a superseded assignment before execution, avoiding dict / Path composition.
repair=repair.replace("        manifest_path=source/'config/deps_manifest.toml'\n        # source was reassigned to the decoded helper bundle above.\n",'')
assert needle in s;s=s.replace(needle,repair+needle)
s=s.replace('runtime_supervisor010.py','runtime_supervisor014.py').replace('runtime-code010','runtime-code014')
# Keep the already-installed run.sh bytes: it is a socket client with identical behavior.
s=s.replace("str(BASE/'runtime-code014/benchmark_client008.py')+' ","str(BASE/'runtime-code010/benchmark_client008.py')+' ")
runtime=(H/'runtime_supervisor010.py').read_text(encoding='utf-8')
runtime=runtime.replace("'API_ADDR':'127.0.0.1:18080'","'XTABLES_LOCKFILE':str(IPC/'xtables014.lock'),'API_ADDR':'127.0.0.1:18080'")
needle="    for mode in ('api-inside','egress-inside','benchmark'):"
preflight='''    command_rows=json.loads((BASE/'config/runtime-command-proof014.json').read_text())
    checks=[]
    for row in command_rows:
        found=shutil.which(row['command'],path=environment['PATH'])
        require(found is not None,'Required command missing inside runtime: '+row['command'])
        require(str(pathlib.Path(found).resolve(strict=True))==row['resolved'],'Runtime command target differs: '+row['command'])
        checks.append({'command':row['command'],'resolved':row['resolved']})
    versions={}
    for name in ('iptables-restore','iptables-save'):
        probe=subprocess.run([shutil.which(name,path=environment['PATH']),'--version'],env=environment,
            capture_output=True,text=True,timeout=15)
        require(probe.returncode==0,'Native firewall executable failed: '+name+' '+probe.stderr[-1000:])
        versions[name]=probe.stdout.strip()
    (IPC/'runtime-preflight014.json').write_text(json.dumps({'uid':os.geteuid(),'netns':os.stat('/proc/self/ns/net').st_ino,
        'commands':checks,'firewallVersions':versions,'xtablesLockfile':environment['XTABLES_LOCKFILE']})+'\\n')
'''
assert needle in runtime;runtime=runtime.replace(needle,preflight+needle)
s=s.replace("        result['runtime_attestation']=", "        result['runtime_preflight']=json.loads((BASE/'r/runtime-preflight014.json').read_text())\n        result['runtime_attestation']=")
for name,body in [('Y_start_runtime014.py',s),('runtime_supervisor014.py',runtime)]:
    ast.parse(body,feature_version=(3,11));(H/name).write_bytes(body.encode())
print('Runtime014 generated: public alternatives, private xtables lock, in-namespace command preflight')
