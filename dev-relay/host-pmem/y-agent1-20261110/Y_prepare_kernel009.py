"""Private package preparation only. No RPM installation or kernel module execution."""
import hashlib,json,os,pathlib,pwd,re,shutil,subprocess,time
P=pathlib.Path;BASE=P('/home/jwk/aenv-agent1-20261110-r2/kernel-prep009')
KERNEL='6.6.0-159.4.3.154.oe2403sp4.x86_64'
def main():
    assert os.geteuid()==0 and os.uname().release==KERNEL
    user=pwd.getpwnam('jwk');os.umask(0o077)
    assert BASE.parent.resolve()==BASE.parent and not BASE.exists(),'Existing preparation preserved'
    BASE.mkdir(mode=0o700);os.chown(BASE,user.pw_uid,user.pw_gid)
    for name in ('cache','persist','logs','downloads'):
        p=BASE/name;p.mkdir(mode=0o700);os.chown(p,user.pw_uid,user.pw_gid)
    state={'action':'PREPARE_MATCHING_KERNEL_INPUTS_ONLY','kernel':KERNEL,'packagesInstalled':False,
      'modulesLoaded':False,'bootChanged':False,'serviceStarted':False,'candidates':[],'downloaded':[]}
    def save():
        p=BASE/'status.json';p.write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n');os.chown(p,user.pw_uid,user.pw_gid)
    def run(args,timeout=30,user_mode=False):
        if user_mode:args=['runuser','-u','jwk','--',*args]
        r=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
        return {'code':r.returncode,'stdout':r.stdout[-16000:],'stderr':r.stderr[-2000:]}
    try:
        # Copy only metadata into a private DNF cache. No writes to /var/cache/dnf.
        root_cache=P('/var/cache/dnf');size=0;files=0
        for root,dirs,names in os.walk(root_cache,followlinks=False):
            dirs[:]=[d for d in dirs if d!='packages' and not (P(root)/d).is_symlink()]
            relative=P(root).relative_to(root_cache);dest=BASE/'cache'/relative;dest.mkdir(parents=True,exist_ok=True,mode=0o700)
            for name in names:
                source=P(root)/name
                if source.is_symlink() or name.endswith(('.lock','.pid')):continue
                size+=source.stat().st_size;files+=1
                assert size<=512*1024**2 and files<=20000,'Metadata cache copy exceeds bound'
                shutil.copyfile(source,dest/name)
        state['private_metadata_copy']={'files':files,'bytes':size};save()
        import dnf,hawkey
        def query(online):
            base=dnf.Base();base.conf.cachedir=str(BASE/'cache');base.conf.persistdir=str(BASE/'persist')
            base.conf.logdir=str(BASE/'logs');base.conf.plugins=False;base.conf.cacheonly=not online
            base.read_all_repos()
            for repo in base.repos.iter_enabled():
                if repo.id not in ('OS','everything','update','source','update-source'):repo.disable()
                else:repo.sslverify=False
            base.fill_sack(load_system_repo=False)
            packages=list(base.sack.query().available().filter(name=['kernel-devel','kernel-source','kernel']))
            rows=[]
            for package in packages:
                if str(package.version)+'-'+str(package.release)!='6.6.0-159.4.3.154.oe2403sp4':continue
                if package.name=='kernel' and package.arch!='src':continue
                if package.arch not in ('x86_64','noarch','src'):continue
                checksum=package.chksum
                rows.append({'name':package.name,'version':str(package.version),'release':str(package.release),
                  'arch':package.arch,'repo':package.reponame,'url':package.remote_location(),'bytes':int(package.downloadsize),
                  'checksum_type':hawkey.chksum_name(checksum[0]),'checksum':bytes(checksum[1]).hex()})
            base.close();return rows
        try:state['candidates']=query(False)
        except Exception as error:state['cached_query_error']=type(error).__name__+': '+str(error)[:500]
        have_devel=any(p['name']=='kernel-devel' for p in state['candidates'])
        have_source=any(p['name']=='kernel-source' or p['arch']=='src' for p in state['candidates'])
        if not(have_devel and have_source):state['candidates']=query(True)
        save()
        def preferred(rows):return sorted(rows,key=lambda p:(p['repo']!='OS',p['repo'],p['url']))[0] if rows else None
        devel=preferred([p for p in state['candidates'] if p['name']=='kernel-devel' and p['arch']=='x86_64'])
        source=preferred([p for p in state['candidates'] if p['name']=='kernel-source'])
        if source is None:source=preferred([p for p in state['candidates'] if p['name']=='kernel' and p['arch']=='src'])
        if devel is None or source is None:
            state['state']='EXACT_KERNEL_INPUTS_NOT_AVAILABLE';save();print(json.dumps(state,ensure_ascii=False));return
        selected=[devel,source];assert sum(p['bytes'] for p in selected)<=2*1024**3
        for package in selected:
            filename=package['url'].rsplit('/',1)[-1]
            assert re.fullmatch('[A-Za-z0-9_.+%-]+\.rpm',filename)
            path=BASE/'downloads'/filename;assert not path.exists()
            result=run(['curl','-k','-fLsS','--connect-timeout','10','--max-time','900','--retry','1',
              '--max-filesize',str(package['bytes']+1024),package['url'],'-o',str(path)],timeout=1850,user_mode=True)
            assert result['code']==0,'Matching package download failed: '+result['stderr']
            algorithm=package['checksum_type'].lower();assert algorithm in hashlib.algorithms_available
            digest=hashlib.new(algorithm)
            with path.open('rb') as f:
                for b in iter(lambda:f.read(1024**2),b''):digest.update(b)
            assert digest.hexdigest()==package['checksum'],'Repository package checksum differs'
            signature=run(['rpm','--checksig','--verbose',str(path)])
            row={**package,'path':str(path),'signature':signature};state['downloaded'].append(row);save()
            assert signature['code']==0 and re.search(r'Signature.*:\s*OK',signature['stdout'],re.I),'Trusted RPM signature not confirmed'
            identity=run(['rpm','-qp','--qf','%{NAME} %{VERSION}-%{RELEASE}.%{ARCH}\n',str(path)])
            row['package_identity']=identity
            assert identity['code']==0 and '6.6.0-159.4.3.154.oe2403sp4' in identity['stdout'],'Package header does not match running kernel'
            row['file_list']=run(['rpm','-qpl',str(path)])
            save()
        state['state']='MATCHING_KERNEL_PACKAGES_PREPARED_NOT_INSTALLED';save();print(json.dumps(state,ensure_ascii=False))
    except Exception as error:
        state['state']='PREPARATION_STOPPED_PRESERVE_INPUTS';state['error_type']=type(error).__name__;state['reason']=str(error)[:700]
        save();print(json.dumps(state,ensure_ascii=False));raise
if __name__=='__main__':main()
