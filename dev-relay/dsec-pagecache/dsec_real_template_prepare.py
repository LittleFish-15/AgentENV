"""Read retained inputs for the next real-template DSec comparison on node A.

No SDK, Guest, service API, shell command, image rewrite, rebuild, or cache drop.
This does not repeat the completed synthetic comparison. Image hashes are only
reported as declared; large images are not fully scanned by this preparation.
"""
import hashlib,json,os,socket,stat,struct
from pathlib import Path

ROOT=Path('/home/jwk/agent')
REPORTS=(
    'builds/native-four-inputs-v1/return.json',
    'builds/native-four-release-v1/return.json',
    'builds/content-observer-release-v2/return.json',
    'r/pm-a-v1/tools-runtime/return.json',
    'builds/rootfs-compact-v1/return.json',
    'builds/rootfs-compact-finish-v2/return.json',
)
IMAGES=tuple('builds/native-four-inputs-v1/case-'+str(i)+'/raw/rootfs.ext4' for i in range(4))+( 
    'builds/rootfs-compact-v1/rootfs.ext4',
    'builds/rootfs-compact-finish-v2/rootfs.ext4',
)


def owned(path,limit):
    path=Path(path)
    if not path.is_absolute() or not path.is_relative_to(ROOT) or path.resolve(strict=True)!=path:
        raise ValueError('Redirected or outside retained input')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=1204 or not 0<info.st_size<=limit:
            raise ValueError('Unexpected retained input type/owner/size')
        return os.fdopen(fd,'rb'),info
    except BaseException:
        os.close(fd);raise


def read_json(path):
    stream,before=owned(path,2*1024**2)
    with stream:
        raw=stream.read(2*1024**2+1);after=os.fstat(stream.fileno())
    stamp=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)
    if stamp(before)!=stamp(after) or len(raw)!=before.st_size:raise ValueError('Input changed')
    value=json.loads(raw)
    if not isinstance(value,dict):raise ValueError('Expected report object')
    return value,hashlib.sha256(raw).hexdigest()


def ext4_header(data,file_bytes):
    if len(data)!=1024 or struct.unpack_from('<H',data,56)[0]!=0xef53:
        return {'ext4':False}
    log=struct.unpack_from('<I',data,24)[0]
    if log>6:raise ValueError('Invalid filesystem block size')
    block=1024<<log
    incompat=struct.unpack_from('<I',data,96)[0]
    blocks=struct.unpack_from('<I',data,4)[0]
    if incompat&0x80:blocks|=struct.unpack_from('<I',data,0x150)[0]<<32
    total,free=struct.unpack_from('<I',data,0)[0],struct.unpack_from('<I',data,16)[0]
    if free>total:raise ValueError('Invalid inode counts')
    return {'ext4':True,'blockBytes':block,'filesystemBytes':blocks*block,
            'fitsFile':blocks*block<=file_bytes,'allocatedInodes':total-free,
            'stateBits':struct.unpack_from('<H',data,58)[0],
            'journalRecoveryNeeded':bool(incompat&4),'inlineDataFeature':bool(incompat&0x8000),
            'pmemMetadataEstimateBytesAt64ByteStructPage':(file_bytes+4095)//4096*64,
            'estimateIsTargetMeasurement':False,'filesystemConsistencyAccepted':False}


def image_metadata(path,header=False):
    stream,info=owned(path,128*1024**3)
    with stream:
        result={'path':str(path),'bytes':info.st_size,'allocatedFileBytes':getattr(info,'st_blocks',0)*512,
                'mtimeNs':info.st_mtime_ns,'contentHashVerified':False}
        if header:
            stream.seek(1024)
            result['filesystem']=ext4_header(stream.read(1024),info.st_size)
        after=os.fstat(stream.fileno())
    if (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):
        raise ValueError('Input changed during metadata read')
    return result


def artifact_rows(value,depth=0):
    if depth>6:return []
    result=[]
    if isinstance(value,dict):
        path=value.get('path')
        if isinstance(path,str) and path.startswith(ROOT.as_posix()+'/'):
            row={k:value[k] for k in ('path','bytes','sha256') if k in value}
            try:row['observed']=image_metadata(Path(path))
            except (OSError,ValueError) as e:row['observed']={'errorType':type(e).__name__}
            result.append(row)
        for key in ('release','binaries','artifacts','nativeImage','cases','server','daemon',
                    'cli','firecracker','verifier','runtime','kernel','tools','image'):
            if key in value:result.extend(artifact_rows(value[key],depth+1))
        for key in ('imagePath','outputImage'):
            if isinstance(value.get(key),str) and value[key].startswith(ROOT.as_posix()+'/'):
                try:result.append(image_metadata(Path(value[key])))
                except (OSError,ValueError) as e:result.append({'path':value[key],'errorType':type(e).__name__})
    elif isinstance(value,list):
        for row in value[:16]:result.extend(artifact_rows(row,depth+1))
    return result[:64]


def report_summary(value):
    result={k:value[k] for k in ('status','revision','coreCommit','coreTree','mode',
        'lowerFilesystem','originalUnchanged','sourceImage') if k in value}
    if isinstance(value.get('release'),dict):
        result['release']={k:value['release'][k] for k in ('coreCommit','tree') if k in value['release']}
    if isinstance(value.get('cases'),list):
        result['cases']=[{k:row[k] for k in ('templateIndex','resources','sourceImage','sourceConfig','nativeImage')
                          if k in row} for row in value['cases'][:4]]
    if isinstance(value.get('phases'),dict):
        result['phases']={k:{x:row[x] for x in ('exitCode','seconds') if x in row}
                          for k,row in list(value['phases'].items())[:16] if isinstance(row,dict)}
    result['artifacts']=artifact_rows(value)
    return result


def main():
    if os.getuid()!=os.geteuid() or os.getuid()!=1204 or socket.gethostname()!='server1':
        raise RuntimeError('Use the ordinary A-node experiment user')
    result={'revision':'dsec-real-template-inputs-v1','readonly':True,'SDK_called':False,
            'Guest_created':False,'services_changed':False,'imagesModified':False,
            'largeImagesFullyHashed':False,'reports':{},'images':{}}
    for name in REPORTS:
        try:
            value,pin=read_json(ROOT/name)
            result['reports'][name]=dict(report_summary(value),reportSha256=pin)
        except (OSError,ValueError) as e:result['reports'][name]={'errorType':type(e).__name__}
    for name in IMAGES:
        try:result['images'][name]=image_metadata(ROOT/name,True)
        except (OSError,ValueError) as e:result['images'][name]={'errorType':type(e).__name__}
    # Recover the omitted same-file map evidence from the completed run in the
    # same pass. Do not start another synthetic experiment or scan live PIDs.
    try:
        previous,pin=read_json(ROOT/'r/dsec-host-pagecache-node-a-v1/results/return.json')
        if previous.get('status')!='DSEC_HOST_PAGECACHE_COMPONENT_COMPLETED_NOT_CROSS_NODE_COW':
            raise ValueError('Completed DSec run required')
        groups=[]
        for group in previous['groups']:
            samples=[]
            for sample in group.get('hostSamples',[]):
                samples.append({k:sample[k] for k in ('sample','monotonicNs','selectedFC','lowerFile','privateUppers') if k in sample})
            groups.append({'mode':group['mode'],'N':group['N'],'samples':samples})
        result['completedDsecEvidence']={'sha256':pin,'groups':groups}
    except (OSError,ValueError) as e:result['completedDsecEvidence']={'errorType':type(e).__name__}
    result['status']='RETAINED_REAL_TEMPLATE_INPUTS_OBSERVED_NO_NEW_TEST'
    print('BEGIN_DSEC_REAL_TEMPLATE_PREPARATION')
    print(json.dumps(result,indent=2))
    print('END_DSEC_REAL_TEMPLATE_PREPARATION')


if __name__=='__main__':main()
