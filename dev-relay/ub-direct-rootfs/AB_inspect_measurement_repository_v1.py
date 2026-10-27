"""Bounded read-only original/retained repository metadata for measurement admission."""
import hashlib,json,os,platform,stat,subprocess,tomllib
from pathlib import Path
ROOT=Path('/home/jwk/agent')
SID='01a15c9e-54d0-7b92-a50b-0b6ec2e9136b'

def small(path,limit):
    with path.open('rb') as stream:
        before=os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size>limit:raise ValueError('Unexpected metadata type/size')
        raw=stream.read(limit+1);after=os.fstat(stream.fileno())
    if (before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):
        raise ValueError('Metadata changed during read')
    return raw

def record(repo,pid=None):
    path=repo/'catalog/records'/(SID+'.json')
    if pid:path=Path('/proc')/str(pid)/'root'/str(path).lstrip('/')
    result={'repository':str(repo),'view':'runtime-mount' if pid else 'host'}
    try:
        raw=small(path,2*1024**2);value=json.loads(raw)
        result.update(present=True,sha256=hashlib.sha256(raw).hexdigest(),id=value.get('id'),resources=value.get('resources'),
            rootfsLayerCount=len(value.get('committed',{}).get('rootfs_layers',[])),
            memoryLayerCount=len(value.get('committed',{}).get('memory_layers',[])))
    except FileNotFoundError:result.update(present=False,repositoryDirectoryPresent=path.parent.parent.parent.is_dir(),recordsDirectoryPresent=path.parent.is_dir())
    except Exception as error:result.update(errorType=type(error).__name__,reason=str(error))
    return result

def main():
    assert os.getuid()==os.geteuid()==0,'Use root'
    node={'server1':'a','agent1':'b'}[platform.node()]
    result={'status':'MEASUREMENT_REPOSITORY_READ_ONLY','node':node,'templateId':SID,
            'stateChanged':False,'GuestCreated':False,'SDKCalled':False,'payloadContentsRead':False,'runtimes':[]}
    for variant,name,unit_prefix in (
        ('original','agentenv-ae9c626-baseline','jwk-aenv-ae9c626-node-'),
        ('full','agentenv-direct-ub-deletefix-v1','jwk-aenv-direct-ub-deletefix-v1-node-')):
        base=ROOT/'deployments'/name;unit=unit_prefix+node+'.service'
        row={'variant':variant,'unit':unit};result['runtimes'].append(row)
        try:
            out=subprocess.run(['systemctl','show',unit,'--property=MainPID,ActiveState,ControlGroup','--no-pager'],check=True,capture_output=True,text=True,timeout=15)
            fields=dict(x.split('=',1) for x in out.stdout.splitlines() if '=' in x);row['unitState']=fields
            pid=int(fields['MainPID']);assert pid>1 and fields['ActiveState']=='active','Expected Runtime inactive'
            proc=Path('/proc')/str(pid);ticks=(proc/'stat').read_text().rsplit(')',1)[1].split()[19];row['startTicks']=ticks
            env=dict(x.split(b'=',1) for x in (proc/'environ').read_bytes().split(b'\0') if b'=' in x)
            row['repositoryEnvironment']={key:env[key.encode()].decode() for key in ('AENV_HOME','AENV_SNAPSHOT_STORE') if key.encode() in env}
            raw=small(base/'config/runtime.toml',1024**2);cfg=tomllib.loads(raw.decode())
            row['configSha256']=hashlib.sha256(raw).hexdigest()
            store=cfg.get('backend',{}).get('posix_fs',{}).get('snapshot_store')
            row['repositoryConfig']={'home_path':cfg.get('home_path'),'repository_backend':cfg.get('snapshot',{}).get('repository_backend'),'snapshot_store':store}
            paths={base/'state/snapshot-store/repository'}
            for value in (store,row['repositoryEnvironment'].get('AENV_SNAPSHOT_STORE')):
                if isinstance(value,str) and Path(value).is_absolute() and Path(value).is_relative_to(ROOT):paths.add(Path(value)/'repository')
            for value in (cfg.get('home_path'),row['repositoryEnvironment'].get('AENV_HOME')):
                if isinstance(value,str) and Path(value).is_absolute() and Path(value).is_relative_to(ROOT):paths.add(Path(value)/'snapshot-store/repository')
            row['records']=[record(p,view) for p in sorted(paths) for view in (None,pid)]
            row['processStable']=(proc/'stat').read_text().rsplit(')',1)[1].split()[19]==ticks
        except Exception as error:row.update(errorType=type(error).__name__,reason=str(error))
    source=ROOT/'deployments/agentenv-lazy-four-32ce41c'
    result['retainedSourceRecord']=record(source/'state/snapshot-store/repository')
    print('BEGIN_MEASUREMENT_REPOSITORY_READ_ONLY')
    print(json.dumps(result,indent=2));print('END_MEASUREMENT_REPOSITORY_READ_ONLY')

if __name__=='__main__':main()
