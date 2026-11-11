"""Read only owned runtime/template diagnostics after failed native build015."""
import http.client,json,os,pathlib,re,stat,subprocess,time
P=pathlib.Path;BASE=P('/home/jwk/aenv-y-clean-20261111');ROOT=P('/run/jwk-aenv-y-clean-20261111')
UNIT='jwk-aenv-y-clean-20261111.service'
def main():
    assert os.getuid()==os.geteuid()==0
    failed=json.loads((BASE/'wikidata015/result.json').read_text())
    assert not failed['success'] and not failed['benchmarkRun'] and failed['buildStatus']['status']=='error'
    sid=failed['templateId'];bid=failed['buildId'];assert re.fullmatch(r'[0-9a-f-]{36}',sid) and re.fullmatch(r'[0-9a-f-]{36}',bid)
    key=(BASE/'config/api-key').read_text().strip()
    def clean(value):
        text=str(value).replace(key,'[REDACTED_API_KEY]')
        return re.sub(r'(https?://)[^/@\s]+:[^/@\s]+@',r'\1[REDACTED]@',text)
    result={'action':'READ_ONLY_OWN_TEMPLATE_DIAGNOSIS','templateId':sid,'buildId':bid,'mutations':False,'logs':{},'commands':{}}
    def call(label,args):
        try:
            row=subprocess.run(args,env={'PATH':'/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin','LANG':'C.UTF-8'},capture_output=True,text=True,timeout=30)
            result['commands'][label]={'code':row.returncode,'stdout':clean(row.stdout[-50000:]),'stderr':clean(row.stderr[-4000:])}
        except Exception as e:result['commands'][label]={'error':type(e).__name__}
    for name in (UNIT,'jwk-aenv-y-devices-20261111.service','jwk-aenv-y-relays-20261111.service'):
        call(name,['systemctl','show',name,'-p','MainPID','-p','ActiveState','-p','SubState','-p','Result'])
    call('runtimeJournal',['journalctl','-u',UNIT,'--no-pager','-n','100','-o','short-iso'])
    call('brokerJournal',['journalctl','-u','jwk-aenv-y-devices-20261111.service','--no-pager','-n','60','-o','short-iso'])
    paths=[BASE/'logs/server.log',BASE/'logs/ublk-daemon.log',BASE/'logs/overlaybd-native.log',BASE/'logs/launcher.log',ROOT/'broker.log']
    candidates=[]
    for directory in (BASE/'logs',BASE/'fc'):
        for count,path in enumerate(directory.rglob('*')):
            if count>10000:break
            try:
                st=path.lstat()
                if stat.S_ISREG(st.st_mode) and path.suffix=='.log':candidates.append((st.st_mtime,path))
            except OSError:pass
    paths+= [path for _,path in sorted(candidates,reverse=True)[:18]]
    for path in dict.fromkeys(paths):
        try:
            assert not path.is_symlink()
            st=path.stat();assert stat.S_ISREG(st.st_mode)
            with path.open('rb') as f:f.seek(max(0,st.st_size-65536));raw=f.read(65536)
            result['logs'][str(path)]={'size':st.st_size,'mtime':st.st_mtime,'tail':clean(raw.decode(errors='replace'))}
        except (OSError,AssertionError) as error:result['logs'][str(path)]={'error':type(error).__name__}
    result['api']={}
    for label,path in [('health','/health'),('inventory','/v2/sandboxes?limit=100'),('build','/templates/'+sid+'/builds/'+bid+'/status')]:
        conn=http.client.HTTPConnection('127.0.0.1',18080,timeout=20)
        try:
            conn.request('GET',path,headers={'X-API-Key':key});response=conn.getresponse();raw=response.read(65536)
            result['api'][label]={'status':response.status,'body':clean(raw.decode(errors='replace'))}
        except Exception as error:result['api'][label]={'error':type(error).__name__}
        finally:conn.close()
    print(json.dumps(result,ensure_ascii=False),flush=True)
if __name__=='__main__':main()
