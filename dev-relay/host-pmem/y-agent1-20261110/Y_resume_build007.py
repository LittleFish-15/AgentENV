"""Resume prepared build with explicit per-command Cargo TLS configuration."""
import hashlib,importlib.util,json,os,pathlib,pwd,time,urllib.parse
P=pathlib.Path
PREVIOUS_JOB='y-agent1-compile-20261110-003-node-y'
PREVIOUS_SHA='56b531f5bb84f64a47653e5b282937681bacd790e7fa85994a197aee7a8b507f'
def prepare_private_ca(b,environment):
    import re
    directory=b.BASE/'network-ca005';b.mkdir(directory)
    bundle=directory/'bundle.pem';parts=[];seen=set();records=[]
    for path in ('/etc/pki/tls/certs/ca-bundle.crt','/etc/ssl/certs/ca-certificates.crt','/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem'):
        p=P(path)
        if not p.is_file() or p.stat().st_size>4*1024**2:continue
        raw=p.read_bytes();digest=hashlib.sha256(raw).hexdigest()
        if b'PRIVATE KEY' in raw or digest in seen:continue
        seen.add(digest);parts.append(raw);records.append({'source':str(p),'sha256':digest,'kind':'existing_system_bundle'})
    for root in ('/etc/pki/ca-trust/source/anchors','/usr/local/share/ca-certificates'):
        directory_source=P(root)
        if not directory_source.is_dir():continue
        for p in sorted(directory_source.iterdir())[:100]:
            if not p.is_file() or p.suffix not in ('.crt','.pem') or p.stat().st_size>128*1024:continue
            raw=p.read_bytes();digest=hashlib.sha256(raw).hexdigest()
            if b'PRIVATE KEY' in raw or b'BEGIN CERTIFICATE' not in raw or digest in seen:continue
            seen.add(digest);parts.append(raw);records.append({'source':str(p),'sha256':digest,'kind':'existing_local_anchor'})
    def save_bundle():
        bundle.write_bytes(b'\n'.join(parts));os.chown(bundle,b.JWK.pw_uid,b.JWK.pw_gid);os.chmod(bundle,0o600)
    def strict_probe():
        return b.probe(['curl','--cacert',str(bundle),'-fLsS','--connect-timeout','10','--max-time','25','-o','/dev/null',
          '-w','HTTP %{http_code}; ssl_verify %{ssl_verify_result}\n','https://index.crates.io/config.json'],environment,seconds=30)
    save_bundle();result=strict_probe()
    if result.get('code')!=0 or 'HTTP 200' not in result.get('stdout',''):
        # User explicitly authorized -k for this environment. Obtain public chain
        # certificates through that approved transport; never install them system-wide.
        chain=b.probe(['curl','-k','--proxy-insecure','-fLsS','--connect-timeout','10','--max-time','25','-o','/dev/null',
          '-w','%{certs}','https://index.crates.io/config.json'],environment,seconds=30)
        assert chain.get('code')==0,'Cannot collect public proxy certificate chain'
        certificates=re.findall(r'-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----',chain.get('stdout',''))
        assert certificates,'No complete certificate chain returned by local curl'
        for i,text in enumerate(certificates):
            p=directory/('observed-chain-'+str(i)+'.pem');p.write_text(text+'\n');os.chown(p,b.JWK.pw_uid,b.JWK.pw_gid)
            info=b.probe(['openssl','x509','-in',str(p),'-noout','-text'],environment)
            if info.get('code')!=0 or 'CA:TRUE' not in info.get('stdout',''):continue
            raw=p.read_bytes();digest=hashlib.sha256(raw).hexdigest()
            if digest in seen:continue
            seen.add(digest);parts.append(raw)
            subject=b.probe(['openssl','x509','-in',str(p),'-noout','-subject','-issuer','-dates'],environment)
            records.append({'source':'public_chain_observed_via_user_approved_insecure_transport','sha256':digest,
              'metadata':subject.get('stdout','')})
        save_bundle();result=strict_probe()
    b.STATE['private_ca005']={'path':str(bundle),'sha256':b.sha_file(bundle),'sources':records,'strict_curl_probe':result,
      'system_trust_changed':False,'observed_chain_trust_basis':'user previously explicitly authorized -k; private scope only'};b.save()
    assert result.get('code')==0 and 'HTTP 200' in result.get('stdout',''),'Private CA did not pass strict registry probe; compilation not retried'
    return str(bundle)

def prefill_registry(b,environment,prefix,ca):
    import concurrent.futures,threading,tomllib
    lock=tomllib.loads((b.SOURCE/'Cargo.lock').read_text())
    packages=[p for p in lock['package'] if p.get('source','').startswith('registry+')]
    cache_root=b.BASE/'deps/cargo/registry/cache'
    dirs=[p for p in cache_root.glob('index.crates.io-*') if p.is_dir()]
    assert len(dirs)==1,'Need one unambiguous crates.io cache directory'
    cache=dirs[0];missing=[];valid=0
    for p in packages:
        target=cache/(p['name']+'-'+p['version']+'.crate')
        if target.is_file() and b.sha_file(target)==p['checksum']:valid+=1
        else:missing.append(p)
    b.STATE['prefill006']={'registry_packages':len(packages),'already_valid':valid,'missing':len(missing),'completed':0,'failures':[]};b.save()
    print(json.dumps({'phase':'registry_prefill006','already_cached':valid,'missing':len(missing)}),flush=True)
    def download(p):
        name=p['name'];version=p['version'];target=cache/(name+'-'+version+'.crate')
        urls=['https://static.crates.io/crates/'+name+'/'+name+'-'+version+'.crate',
          'https://crates.io/api/v1/crates/'+name+'/'+version+'/download',
          'https://static.crates.io/crates/'+name+'/'+version+'/download']
        attempts=[]
        for i,url in enumerate(urls):
            temp=target.with_name(target.name+'.prefill006-'+str(i))
            result=b.probe(prefix+['curl','--cacert',ca,'-fLsS','--connect-timeout','10','--max-time','45',
              '--retry','1','--retry-delay','1','--max-filesize','268435456',url,'-o',str(temp)],environment,seconds=100)
            if result.get('code')==0 and temp.is_file() and b.sha_file(temp)==p['checksum']:
                if target.exists():
                    assert target.stat().st_uid==b.JWK.pw_uid and not target.is_symlink()
                    backup=target.with_name(target.name+'.before-prefill006')
                    assert not backup.exists(),'Existing invalid-cache backup requires review'
                    os.rename(target,backup)
                os.replace(temp,target)
                return {'name':name,'version':version,'checksum':p['checksum'],'success':True,'url':url}
            attempts.append({'url':url,'code':result.get('code'),'error':result.get('stderr','')[-350:],
              'checksum_match':temp.is_file() and b.sha_file(temp)==p['checksum']})
        return {'name':name,'version':version,'checksum':p['checksum'],'success':False,'attempts':attempts}
    results=[];begun=time.monotonic();last=begun
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures=[executor.submit(download,p) for p in missing]
        for future in concurrent.futures.as_completed(futures):
            assert os.getppid()==b.PARENT,'Entry supervisor exited during dependency prefill'
            row=future.result();results.append(row)
            if not row['success']:b.STATE['prefill006']['failures'].append(row)
            b.STATE['prefill006']['completed']=len(results)
            now=time.monotonic()
            if now-last>=20 or len(results)==len(missing):
                b.save();print(json.dumps({'phase':'registry_prefill006','completed':len(results),'total':len(missing),
                  'failed':len(b.STATE['prefill006']['failures']),'elapsed_seconds':round(now-begun)}),flush=True);last=now
    path=b.BASE/'registry-prefill006-results.json'
    path.write_text(json.dumps(results,indent=2)+'\n');os.chown(path,b.JWK.pw_uid,b.JWK.pw_gid)
    b.save()
    assert not b.STATE['prefill006']['failures'],'Some exact locked crates remain unavailable; offline compilation not started'

SHIPPED_PACKAGES=[{'name': 'aws-sdk-s3', 'version': '1.119.0', 'checksum': '1d65fddc3844f902dfe1864acb8494db5f9342015ee3ab7890270d36fbd2e01c', 'bytes': 1608532, 'parts': [{'repo': 'LittleFish-15/AgentENV', 'path': 'dev-relay/host-pmem/y-agent1-20261110/crate007-aws-sdk-s3-001.bin', 'commit': '3fb0d849f020b9d0d1c1fba3d0ad3306b8f68cd0', 'sha256': '1e90fdc2cd079e326352fa1cfbc5cd9c357c94b17b3bee7531988a4e7d3e029c', 'bytes': 716800, 'blob': '92102591c674e3698e5ee6887ee9d85a2046685e'}, {'repo': 'LittleFish-15/AgentENV', 'path': 'dev-relay/host-pmem/y-agent1-20261110/crate007-aws-sdk-s3-002.bin', 'commit': '3fb0d849f020b9d0d1c1fba3d0ad3306b8f68cd0', 'sha256': '5c59abea233ffde8307b0cb7ec39160dde680a30917096c9d4d22a7af9f0ac2b', 'bytes': 716800, 'blob': '36d72b80c63669977aadfd3bfe41adf75a343670'}, {'repo': 'LittleFish-15/AgentENV', 'path': 'dev-relay/host-pmem/y-agent1-20261110/crate007-aws-sdk-s3-003.bin', 'commit': '3fb0d849f020b9d0d1c1fba3d0ad3306b8f68cd0', 'sha256': 'fbf9612355d5fe3d821d7682a794121df9752562717ecc57ae16bb9438dbb29f', 'bytes': 174932, 'blob': '53813d77bd4e7370d29661f53b9dba39c1d24d61'}]}, {'name': 'librocksdb-sys', 'version': '0.17.3+10.4.2', 'checksum': 'cef2a00ee60fe526157c9023edab23943fae1ce2ab6f4abb2a807c1746835de9', 'bytes': 7074228, 'parts': [{'repo': 'LittleFish-15/AgentENV', 'path': 'dev-relay/host-pmem/y-agent1-20261110/crate007-librocksdb-sys-001.bin', 'commit': '3fb0d849f020b9d0d1c1fba3d0ad3306b8f68cd0', 'sha256': '885288e1812f4f6602a582fa705faf0505fc169c866f91243931332f1143267f', 'bytes': 716800, 'blob': 'a8ec968375968eb84e19945d73713a07623f848d'}, {'repo': 'LittleFish-15/AgentENV', 'path': 'dev-relay/host-pmem/y-agent1-20261110/crate007-librocksdb-sys-002.bin', 'commit': '3fb0d849f020b9d0d1c1fba3d0ad3306b8f68cd0', 'sha256': 'd136603053888dba70ca83e9857565828649e3d5f1205d021c0e027d92cab7bb', 'bytes': 716800, 'blob': 'd1d22f2269cfc09c75439856378a0337cc0de62e'}, {'repo': 'LittleFish-15/AgentENV', 'path': 'dev-relay/host-pmem/y-agent1-20261110/crate007-librocksdb-sys-003.bin', 'commit': '3fb0d849f020b9d0d1c1fba3d0ad3306b8f68cd0', 'sha256': '79efe8681966124327443c11b0151a86bf7e2e5e54e23007b31fd6bcc3b6f3fa', 'bytes': 716800, 'blob': '4b557d236083f35f4b4a3352f1a2c905c813a86d'}, {'repo': 'LittleFish-15/AgentENV', 'path': 'dev-relay/host-pmem/y-agent1-20261110/crate007-librocksdb-sys-004.bin', 'commit': '3fb0d849f020b9d0d1c1fba3d0ad3306b8f68cd0', 'sha256': '52848e46b48c307237cb95f42de0cacc633683e79cca7befd7aa64c38fc30277', 'bytes': 716800, 'blob': 'ad86cdff2285591aa75b61f4cd23c7aeb5968957'}, {'repo': 'LittleFish-15/AgentENV', 'path': 'dev-relay/host-pmem/y-agent1-20261110/crate007-librocksdb-sys-005.bin', 'commit': '3fb0d849f020b9d0d1c1fba3d0ad3306b8f68cd0', 'sha256': 'f51129a32aec554f671212a70a68db5597b1164eaecfa8f5b5c77045b531cb7f', 'bytes': 716800, 'blob': '2837c5f54c7a8ae879de0844c663daca40630be4'}, {'repo': 'LittleFish-15/AgentENV', 'path': 'dev-relay/host-pmem/y-agent1-20261110/crate007-librocksdb-sys-006.bin', 'commit': '3fb0d849f020b9d0d1c1fba3d0ad3306b8f68cd0', 'sha256': '3ce8311b1ad3c53375b3b6665294d89d3f3911e91cad2dec535c9fb858ad9349', 'bytes': 716800, 'blob': '38bc2a7f57e4144f54c7b20e2c17530a6e8de4cb'}, {'repo': 'LittleFish-15/AgentENV', 'path': 'dev-relay/host-pmem/y-agent1-20261110/crate007-librocksdb-sys-007.bin', 'commit': '3fb0d849f020b9d0d1c1fba3d0ad3306b8f68cd0', 'sha256': '9e61684ccf267c48f854a5d08c90de63c00fd6af70f9383fb8d9bd2de145bb56', 'bytes': 716800, 'blob': '96544179b7ee1546f29b89d0168cdb717aef6e09'}, {'repo': 'LittleFish-15/AgentENV', 'path': 'dev-relay/host-pmem/y-agent1-20261110/crate007-librocksdb-sys-008.bin', 'commit': '3fb0d849f020b9d0d1c1fba3d0ad3306b8f68cd0', 'sha256': '59e7e4929587357fee996eb06329b8d436a73481f9c2741b3fc9b2ab34b97fd4', 'bytes': 716800, 'blob': '7f5b8034df7bd1e8cc5f0f114a299f0ef35fbaca'}, {'repo': 'LittleFish-15/AgentENV', 'path': 'dev-relay/host-pmem/y-agent1-20261110/crate007-librocksdb-sys-009.bin', 'commit': '3fb0d849f020b9d0d1c1fba3d0ad3306b8f68cd0', 'sha256': '39a4499196d8c95c5d51f6a9b4b089d27d3ffdafe8ec46941af1c4c562a825b1', 'bytes': 716800, 'blob': 'd218e06aa12f03af56a911510e3cb77854ccfa8b'}, {'repo': 'LittleFish-15/AgentENV', 'path': 'dev-relay/host-pmem/y-agent1-20261110/crate007-librocksdb-sys-010.bin', 'commit': '3fb0d849f020b9d0d1c1fba3d0ad3306b8f68cd0', 'sha256': 'add89f1b49162998b3f419ad34e01d757d13397fe25d3b769113f28ec3b30e81', 'bytes': 623028, 'blob': '505811868e7eae3f07b949970c874f66a7ad16b1'}]}]

def install_shipped_crates(b):
    import tomllib
    registry=tomllib.loads((b.SOURCE/'Cargo.lock').read_text())['package']
    cache_root=b.BASE/'deps/cargo/registry/cache';dirs=[p for p in cache_root.glob('index.crates.io-*') if p.is_dir()]
    assert len(dirs)==1,'Ambiguous private crates cache';cache=dirs[0]
    git_cache=P('/home/jwk/y-aenv-control/relay-agent1-20261110/source-cache.git')
    assert git_cache.is_dir() and git_cache.stat().st_uid==0
    installed=[]
    for package in SHIPPED_PACKAGES:
        matches=[p for p in registry if p['name']==package['name'] and p['version']==package['version']]
        assert len(matches)==1 and matches[0]['checksum']==package['checksum'],'Delivery differs from Cargo.lock'
        data=[]
        for part in package['parts']:
            r=__import__('subprocess').run(['git','--git-dir='+str(git_cache),'cat-file','blob',part['blob']],capture_output=True,timeout=30)
            assert r.returncode==0 and len(r.stdout)==part['bytes'] and hashlib.sha256(r.stdout).hexdigest()==part['sha256'],'Git-delivered crate part differs'
            data.append(r.stdout)
        raw=b''.join(data);assert len(raw)==package['bytes'] and hashlib.sha256(raw).hexdigest()==package['checksum']
        target=cache/(package['name']+'-'+package['version']+'.crate')
        if target.exists() and b.sha_file(target)==package['checksum']:installed.append({'name':package['name'],'already_cached':True});continue
        if target.exists():
            assert not target.is_symlink() and target.stat().st_uid==b.JWK.pw_uid
            backup=target.with_name(target.name+'.before-git007');assert not backup.exists();os.rename(target,backup)
        temp=target.with_name(target.name+'.git007-next');assert not temp.exists()
        temp.write_bytes(raw);os.chown(temp,b.JWK.pw_uid,b.JWK.pw_gid);os.chmod(temp,0o600);os.replace(temp,target)
        installed.append({'name':package['name'],'version':package['version'],'sha256':package['checksum'],'bytes':len(raw)})
    b.STATE['git_shipped_crates007']=installed;b.save();print(json.dumps({'git_shipped_crates007':installed}),flush=True)

def main():
    assert os.geteuid()==0
    path=P('/home/jwk/y-aenv-control/relay-agent1-20261110/jobs')/PREVIOUS_JOB/'task.py'
    assert path.resolve()==path and path.stat().st_uid==0 and hashlib.sha256(path.read_bytes()).hexdigest()==PREVIOUS_SHA
    spec=importlib.util.spec_from_file_location('verified_previous_build',path);b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
    b.JWK=pwd.getpwnam('jwk');b.STATE=json.loads((b.BASE/'status.json').read_text());b.COMMIT=b.STATE['source_commit']
    assert b.COMMIT=='ae9c62693839ce7effa2b45df31c0039ae4f9fbc' and b.STATE.get('checkout_verified')
    assert not b.STATE.get('compiled') and b.BASE.stat().st_uid==b.JWK.pw_uid
    tc=b.STATE['toolchain'];rustc=P(tc['prefix'])/'bin/rustc';cargo=P(tc['prefix'])/'bin/cargo'
    assert rustc.is_file() and cargo.is_file()
    environment=b.env();environment['PATH']=str(cargo.parent)+':'+environment['PATH'];environment['RUSTC']=str(rustc)
    environment.pop('CARGO_HTTP_SSL_VERIFY',None)
    ca=str(b.BASE/'network-ca005/bundle.pem')
    assert b.sha_file(P(ca))==b.STATE['private_ca005']['sha256'],'Prepared CA bundle changed'
    environment['CARGO_HTTP_CAINFO']=ca;environment['CARGO_HTTP_PROXY_CAINFO']=ca
    enforce={k:environment[k] for k in ('CARGO_HOME','CARGO_TARGET_DIR','RUSTC','CARGO_HTTP_CAINFO','CARGO_HTTP_PROXY_CAINFO','CARGO_NET_GIT_FETCH_WITH_CLI','GIT_CONFIG_COUNT','GIT_CONFIG_KEY_0','GIT_CONFIG_VALUE_0')}
    enforce['CARGO_REGISTRIES_CRATES_IO_PROTOCOL']='sparse'
    # Apply inside runuser, after PAM environment handling; only non-secret settings enter argv.
    prefix=['env',*[k+'='+v for k,v in enforce.items()]]
    b.STATE['resuming_task']='build007';b.STATE['previous_failure']={'reason':b.STATE.get('reason'),'error_type':b.STATE.get('error_type')}
    b.STATE.pop('reason',None);b.STATE.pop('error_type',None);b.save()
    try:
        probe="import os,json,urllib.parse; keys=('CARGO_HTTP_CAINFO','CARGO_HTTP_PROXY_CAINFO','CARGO_NET_GIT_FETCH_WITH_CLI','CARGO_HOME','CARGO_TARGET_DIR');d={k:os.environ.get(k) for k in keys};d['proxies']={k:{'scheme':urllib.parse.urlsplit(v).scheme,'host':urllib.parse.urlsplit(v).hostname,'port':urllib.parse.urlsplit(v).port} for k,v in os.environ.items() if k.lower() in ('http_proxy','https_proxy','all_proxy')};print(json.dumps(d))"
        result=b.probe(prefix+['python3','-c',probe],environment)
        b.STATE['effective_user_build_environment']=result;b.save()
        b.STATE['network_probe']=b.probe(prefix+['curl','-k','--proxy-insecure','-sS','--connect-timeout','10','--max-time','20','-o','/dev/null',
          '-w','HTTP %{http_code}; connect %{http_connect}; ssl_verify %{ssl_verify_result}\n','https://index.crates.io/config.json'],environment,seconds=25)
        b.save()
        status=b.probe(['git','-C',str(b.SOURCE),'status','--porcelain'],environment)
        assert status['code']==0 and not status['stdout'].strip(),'Prepared source changed; preserve before resuming'
        install_shipped_crates(b)
        b.run('cargo-release-build007',prefix+[str(cargo),'--config','http.cainfo='+json.dumps(ca),'--config','http.proxy-cainfo='+json.dumps(ca),'--config','net.git-fetch-with-cli=true',
          'build','--offline','--locked','--release','-j','4','-p','agentenv','-p','aenv','-p','uvm-ublk-daemon',
          '--bin','server','--bin','aenv','--bin','uvm-ublk-daemon'],environment,seconds=9000,cwd=b.SOURCE)
        assert b.sha_file(b.SOURCE/'Cargo.lock')==b.STATE['lockfile_sha256']
        assert not b.probe(['git','-C',str(b.SOURCE),'status','--porcelain'],environment)['stdout'].strip()
        b.STATE['compiled']=True;b.STATE['binaries']={}
        for name in ('server','aenv','uvm-ublk-daemon'):
            built=b.BASE/'target/release'/name;assert built.is_file() and built.stat().st_uid==b.JWK.pw_uid
            typ=b.probe(['file','-b',str(built)]);assert 'x86-64' in typ['stdout']
            b.copy_component(built,b.BASE/'bin'/name,'compiled_binary')
            b.STATE['binaries'][name]={'path':str(b.BASE/'bin'/name),'sha256':b.sha_file(b.BASE/'bin'/name),'file':typ,'ldd':b.probe(['ldd',str(built)])}
        b.run('installed-cli-help004',[str(b.BASE/'bin/aenv'),'--help']);b.run('installed-server-help004',[str(b.BASE/'bin/server'),'--help'])
        b.STATE.update(installed=True,service_started=False,deployment_pending=True,state='COMPILED_READY_FOR_ISOLATED_SERVICE_DEPLOYMENT')
        b.save();print(json.dumps(b.STATE,ensure_ascii=False))
    except Exception as error:
        b.STATE.update(state='BUILD007_STOPPED_PRESERVE_LOGS',error_type=type(error).__name__,reason=str(error)[:500]);b.save()
        print(json.dumps(b.STATE,ensure_ascii=False));raise
if __name__=='__main__':main()
