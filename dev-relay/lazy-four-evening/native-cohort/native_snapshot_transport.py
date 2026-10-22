"""Copy exactly four committed snapshots to an independent inactive repository.

Native archived bases, VM state, private rootfs tails and ordinary memory layers
are retained; copied memory artifacts do not establish cross-node Guest RAM CoW. No live database, source hardlink, Guest or original service mutation.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile

ROOT = Path('/home/jwk/agent')
D = ROOT / 'deployments/agentenv-native-archive-v1'
LIMIT = 64 * 1024**3


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def layer_name(layer):
    need(set(layer) >= {'digest', 'size'} and re.fullmatch(r'sha256:[0-9a-f]{64}', layer['digest'])
         and type(layer['size']) is int and 0 < layer['size'] <= 8 * 1024**3, 'Invalid managed layer')
    return 'managed-layers/' + layer['digest'].replace(':', '_') + '.overlaybd.commit'


def native_files(sid,native):
    need(isinstance(native,dict) and set(native)=={'version','sourceImage','filesystem','layers','archiveVersion'}
         and type(native['version']) is int and native['version']==1
         and type(native['archiveVersion']) is int and native['archiveVersion']==1
         and re.fullmatch(r'sha256:[0-9a-f]{64}',native['sourceImage'])
         and native['filesystem']=='ext4' and isinstance(native['layers'],list)
         and 1<=len(native['layers'])<=8,'Expected portable archived native rootfs')
    files={};seen=set()
    for index,layer in enumerate(native['layers']):
        need(set(layer)=={'sha256','bytes'} and re.fullmatch(r'sha256:[0-9a-f]{64}',layer['sha256'])
             and type(layer['bytes']) is int and 0<layer['bytes']<=4*1024**3 and layer['bytes']%(2*1024**2)==0,
             'Native archive identity/size differs')
        need(layer['sha256'] not in seen,'Repeated native layer');seen.add(layer['sha256'])
        files[f"snapshots/{sid}/native-pmem/{index:02}-{layer['sha256'][7:]}.img"]={'bytes':layer['bytes'],'sha256':layer['sha256'][7:]}
    return files


def snapshot_contract(record,manifest):
    sid=record['id']
    need(re.fullmatch('[0-9a-f-]{36}',sid) and record['resources']['memory_mib']==4096
         and record['resources']['cpu_count']==2,'Wrong native snapshot resources')
    c=record['committed']
    need(re.fullmatch(r'0\.1\.1-[A-Za-z0-9.-]+',c.get('runtime_versions',{}).get('tools_drive_version','')),
         'Explicit native tools version is missing')
    need(not any(c.get(k) for k in ('attached_drives','volume_snapshots','memory_startup')),
         'Additional snapshot dependency requires explicit support')
    need(manifest['memory']['virtualSize']==4096*1024**2 and not manifest.get('attachedDrives')
         and manifest.get('backend','firecracker')=='firecracker','Expected native Firecracker four-GiB snapshot')
    files=native_files(sid,manifest.get('nativeRootfs'))
    need(0<len(c['rootfs_layers'])<=64 and 0<len(c['memory_layers'])<=16,'Unexpected managed layer count')
    roots=[]
    for row in c['rootfs_layers']:
        need(isinstance(row,dict) and set(row)=={'Managed'},'Only committed managed writable layers supported')
        roots.append(row['Managed'])
    for row in [*roots,*c['memory_layers']]:
        name=layer_name(row);desc={'bytes':row['size'],'sha256':row['digest'][7:]}
        need(name not in files or files[name]==desc,'Conflicting layer identity');files[name]=desc
    return files,roots


def safe(path):
    path = Path(path)
    need(path.is_absolute() and path.is_relative_to(ROOT) and path.resolve(strict=True) == path,
         'Unexpected or redirected private input')
    return path


def opened(path, limit=8 * 1024**3):
    fd = os.open(safe(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    stream = os.fdopen(fd, 'rb')
    m = os.fstat(fd)
    if not (stat.S_ISREG(m.st_mode) and m.st_uid == 1204 and 0 < m.st_size <= limit):
        stream.close(); raise RuntimeError('Invalid owned immutable input')
    return stream, m


def stamp(m):
    return m.st_dev, m.st_ino, m.st_size, m.st_mtime_ns, m.st_ctime_ns


def consume(stream, length, target=None):
    h = hashlib.sha256()
    left = length
    while left:
        raw = stream.read(min(left, 1024**2)); need(raw, 'Truncated private input')
        h.update(raw); left -= len(raw)
        if target is not None:
            target.write(raw)
    need(not stream.read(1), 'Private input grew')
    return h.hexdigest()


def read(path):
    stream, before = opened(path, 16 * 1024**2)
    with stream:
        raw = stream.read()
        need(stamp(before) == stamp(os.fstat(stream.fileno())), 'Metadata changed')
        return raw


def descriptor(path):
    stream, before = opened(path)
    with stream:
        digest = consume(stream, before.st_size)
        need(stamp(before) == stamp(os.fstat(stream.fileno())), 'Input changed while hashing')
        return {'bytes': before.st_size, 'sha256': digest}


def inventory(repository,selected,captures):
    need(len(selected)==4 and captures.get('status')=='FOUR_NATIVE_PARENTS_CAPTURED_OWNED_GUESTS_RELEASED'
         and captures.get('node')=='node-a' and len(captures.get('templates',[]))==4,
         'Exactly four completed A native captures required')
    files={};templates=[]
    for index,(case,capture) in enumerate(zip(selected,captures['templates'])):
        sid=capture['nativeTemplateId']
        need(capture['templateIndex']==index and re.fullmatch('[0-9a-f-]{36}',sid),'Invalid captured template identity')
        record_name='catalog/records/'+sid+'.json';raw=read(repository/record_name);record=json.loads(raw)
        evidence=capture['snapshotEvidence']
        need(hashlib.sha256(raw).hexdigest()==evidence['committedRecordSha256'] and evidence['snapshotId']==sid,
             'Captured catalog identity differs')
        manifest_name='snapshots/'+sid+'/firecracker-manifest.json';manifest=json.loads(read(repository/manifest_name))
        dependencies,roots=snapshot_contract(record,manifest)
        need(record['id']==sid and manifest['nativeRootfs']==evidence['nativeRootfs']
             and capture['sourceImage']==manifest['nativeRootfs']['sourceImage']
             and capture['resources']==case['original']['resources']
             and read(repository/'snapshots'/sid/'commit')==b'committed','Capture content/resources/commit differs')
        for name,desc in dependencies.items():
            need(name not in files or files[name]==desc,'Conflicting shared file');files[name]=desc
        for name in (record_name,manifest_name,'snapshots/'+sid+'/vm_state.bin','snapshots/'+sid+'/commit'):
            files[name]=descriptor(repository/name)
        templates.append({'templateIndex':index,'templateId':sid,'catalogSha256':evidence['committedRecordSha256'],
            'instanceId':case['case']['instance_id'],'replaySha256':case['case']['replay_sha256'],
            'resources':capture['resources'],'rootfsLayers':roots,'nativeRootfs':manifest['nativeRootfs'],
            'runtimeVersions':record['committed']['runtime_versions']})
    need(len({t['templateId'] for t in templates})==4,'Repeated captured template')
    return files,templates


def valid_manifest(value):
    need(isinstance(value,dict) and set(value)=={'version','kind','templates','files'} and type(value['version']) is int
         and value['version']==1 and value['kind']=='native-archived-four-snapshots' and len(value['templates'])==4,
         'Invalid native snapshot archive')
    expected={'selection.private.json','historical-reference.private.json','capture-set.private.json'}
    for index,t in enumerate(value['templates']):
        need(t['templateIndex']==index and re.fullmatch('[0-9a-f-]{36}',t['templateId']),'Template identity differs')
        sid=t['templateId'];expected.add('catalog/records/'+sid+'.json')
        expected.update('snapshots/'+sid+'/'+n for n in ('commit','vm_state.bin','firecracker-manifest.json'))
        expected.update(native_files(sid,t['nativeRootfs']))
        expected.update(layer_name(layer) for layer in t['rootfsLayers'])
    need(len({t['templateId'] for t in value['templates']})==4,'Repeated templates')
    files=value['files'];need(isinstance(files,dict) and len(files)<=512 and expected<=set(files),'Missing snapshot dependencies')
    for name,desc in files.items():
        need(name in expected or re.fullmatch(r'managed-layers/sha256_[0-9a-f]{64}\.overlaybd\.commit',name),
             'Unexpected native archive member')
        need(set(desc)=={'bytes','sha256'} and type(desc['bytes']) is int and 0<desc['bytes']<=8*1024**3
             and re.fullmatch('[0-9a-f]{64}',desc['sha256']),'Invalid native archive descriptor')
    for t in value['templates']:
        need(all(files[name]==desc for name,desc in native_files(t['templateId'],t['nativeRootfs']).items()),'Native archive descriptor differs')
    need(sum(d['bytes'] for d in files.values())<=LIMIT,'Native transfer exceeds explicit file budget')
    return files


def pack(repository, selection, history, captures_path, archive):
    selected = json.loads(read(selection))['selected']
    files, templates = inventory(repository, selected, json.loads(read(captures_path)))
    files['selection.private.json'] = descriptor(selection)
    files['historical-reference.private.json'] = descriptor(history)
    files['capture-set.private.json'] = descriptor(captures_path)
    value = {'version': 1, 'kind': 'native-archived-four-snapshots', 'templates': templates, 'files': files}
    valid_manifest(value)
    need(shutil.disk_usage(ROOT).free >= sum(x['bytes'] for x in files.values()) + 8 * 1024**3, 'Archive disk reserve insufficient')
    safe(archive.parent)
    with archive.open('xb') as output, tarfile.open(fileobj=output, mode='w') as tar:
        raw = json.dumps(value, sort_keys=True).encode()
        item = tarfile.TarInfo('manifest.json'); item.size = len(raw); tar.addfile(item, io.BytesIO(raw))
        for name, desc in files.items():
            path = selection if name == 'selection.private.json' else history if name == 'historical-reference.private.json' else captures_path if name == 'capture-set.private.json' else repository / name
            stream, before = opened(path)
            with stream:
                need(before.st_size == desc['bytes'] and consume(stream, before.st_size) == desc['sha256'], 'Snapshot input changed')
                stream.seek(0)
                item = tarfile.TarInfo(name); item.size = before.st_size; item.mode = 0o600
                tar.addfile(item, stream)
                need(stamp(before) == stamp(os.fstat(stream.fileno())), 'Snapshot input changed during copy')
    return value


def receive(archive, pin, target):
    safe(target.parent)
    need(not target.exists() and not target.is_symlink(), 'Existing received snapshot preserved')
    stream, before = opened(archive, LIMIT + 1024**2)
    with stream:
        need(consume(stream, before.st_size) == pin, 'Private archive checksum differs')
        stream.seek(0)
        with tarfile.open(fileobj=stream, mode='r:') as tar:
            members = tar.getmembers()
            need(len(members) <= 513 and all(x.isfile() and not x.issparse() for x in members), 'Unexpected archive member type')
            indexed = {x.name: x for x in members}
            need(len(indexed) == len(members) and 'manifest.json' in indexed and indexed['manifest.json'].size <= 1024**2,
                 'Missing or duplicate archive metadata')
            manifest = json.load(tar.extractfile(indexed['manifest.json']))
            files = valid_manifest(manifest)
            need(set(indexed) == set(files) | {'manifest.json'}, 'Archive member inventory differs')
            need(shutil.disk_usage(ROOT).free >= sum(x['bytes'] for x in files.values()) + 8 * 1024**3, 'Receive disk reserve insufficient')
            target.mkdir(mode=0o700)
            for name, desc in files.items():
                item = indexed[name]; need(item.size == desc['bytes'], 'Member length differs')
                path = target.joinpath(*PurePosixPath(name).parts)
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with tar.extractfile(item) as source, path.open('xb') as output:
                    need(consume(source, item.size, output) == desc['sha256'], 'Snapshot member checksum differs')
                    output.flush(); os.fsync(output.fileno())
        need(stamp(before) == stamp(os.fstat(stream.fileno())), 'Archive changed during receive')
    expected_files = {'selection.private.json', 'historical-reference.private.json', 'capture-set.private.json'}
    for t in manifest['templates']:
        sid = t['templateId']
        record = json.loads(read(target / 'catalog/records' / (sid + '.json')))
        layers, roots = snapshot_contract(record, json.loads(read(target / 'snapshots' / sid / 'firecracker-manifest.json')))
        need(record['id'] == sid and roots == t['rootfsLayers'] and all(files[name] == desc for name, desc in layers.items())
             and files['catalog/records/' + sid + '.json']['sha256'] == t['catalogSha256']
             and read(target / 'snapshots' / sid / 'commit') == b'committed', 'Snapshot dependency differs')
        expected_files.update(layers)
        expected_files.add('catalog/records/' + sid + '.json')
        expected_files.update('snapshots/' + sid + '/' + name for name in ('commit', 'vm_state.bin', 'firecracker-manifest.json'))
    need(set(files) == expected_files, 'Unreferenced managed payload refused')
    dependencies, templates = inventory(target,json.loads(read(target/'selection.private.json'))['selected'],json.loads(read(target/'capture-set.private.json')))
    need(templates==manifest['templates'],'Transferred native capture metadata differs')
    with (target / 'manifest.json').open('x') as output:
        json.dump(manifest, output, indent=2)
    return manifest


def seed(received,node):
    import fcntl,tomllib
    need(node=='node-b','Cross-node snapshot seeding is only into B; A originals are retained')
    definition=json.loads(read(D/'definition-native.json'))
    installation=json.loads(read(D/'installation.json'))
    need(definition['node']==node and installation.get('node')==node and definition.get('rootfsBinding')
         and installation.get('commit')=='5e6621c9c9d2e347959a61a46c7f6d99688eeb55','Native Runtime identity differs')
    lock=os.open(D/'cohort.lock',os.O_RDWR|os.O_NOFOLLOW)
    try:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        need(json.loads(read(D/'cohort-state.json'))=={'version':1,'phase':'prepared','openRequests':[],
             'sandboxIds':[],'outcomeUncertain':False},'Initial empty B cohort required')
        need(subprocess.check_output(['/usr/bin/systemctl','show','jwk-aenv-native-archive-v1-node-b.service',
             '--property=LoadState','--value'],text=True).strip()=='not-found','Seed only before B Runtime starts')
        manifest=json.loads(read(received/'manifest.json'));files=valid_manifest(manifest)
        # Recheck semantic closure immediately before writing repository files.
        selected=json.loads(read(received/'selection.private.json'))['selected']
        captured=json.loads(read(received/'capture-set.private.json'))
        dependencies,templates=inventory(received,selected,captured)
        private={'selection.private.json','historical-reference.private.json','capture-set.private.json'}
        need(templates==manifest['templates'] and {k:v for k,v in files.items() if k not in private}==dependencies,
             'Received snapshot semantic closure changed')
        cfg=tomllib.loads(definition['config']);tools=cfg['tools']['version']
        need(all(t['runtimeVersions']['tools_drive_version']==tools for t in templates),'Native tools version differs on B')
        binding_path=Path(definition['rootfsBinding']['path']);binding_raw=read(binding_path)
        need(hashlib.sha256(binding_raw).hexdigest()==definition['rootfsBinding']['sha256'],'B native binding changed')
        bindings=json.loads(binding_raw)['bindings']
        by_source={b['sourceImage']:b for b in bindings};need(len(by_source)==len(bindings)==4,'Expected four distinct B native bindings')
        for t in templates:
            native=t['nativeRootfs'];bound=by_source[native['sourceImage']]
            need(bound['version']==3 and bound['lowerFilesystem']==native['filesystem']
                 and [{'sha256':x['sha256'],'bytes':x['bytes']} for x in bound['layers']]==native['layers'],'B bound native contents differ')
        target=D/'state/snapshot-store/repository'
        need(not target.exists() and not target.is_symlink(),'Existing/partial B repository preserved')
        need(shutil.disk_usage(D).free>=sum(d['bytes'] for n,d in files.items() if n not in private)+8*1024**3,'B repository disk reserve insufficient')
        target.mkdir(parents=True,mode=0o700)
        names=sorted((n for n in files if n not in private),key=lambda n:(n.startswith('catalog/records/'),n.endswith('/commit'),n))
        for name in names:
            path=target/name;path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            stream,before=opened(received/name)
            with stream,path.open('xb') as output:
                need(before.st_size==files[name]['bytes'] and consume(stream,before.st_size,output)==files[name]['sha256'],
                     'Received native snapshot changed during import')
                need(stamp(before)==stamp(os.fstat(stream.fileno())),'Import source changed')
                output.flush();os.fsync(output.fileno())
            if '/native-pmem/' in name:path.chmod(0o400)
        # Only the inactive Runtime may receive this repository; make child
        # directory entries durable before publishing the import receipt.
        for directory in sorted([p for p in target.rglob('*') if p.is_dir()]+[target],key=lambda p:len(p.parts),reverse=True):
            fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(fd)
            finally:os.close(fd)
        receipt={'status':'A_NATIVE_SNAPSHOTS_SEEDED_ON_INACTIVE_B_NOT_GUEST_ACCEPTANCE','node':node,
            'repository':str(target),'inputDirectory':str(received),'templates':templates,
            'sourceManifestSha256':hashlib.sha256(read(received/'manifest.json')).hexdigest(),
            'sourceNode':'node-a','VMStateCopied':True,'memfileCrossNodeCowAccepted':False,'SDK_called':False,'Guest_created':False}
        with (D/'native-snapshot-inputs.json').open('x') as output:
            json.dump(receipt,output,indent=2);output.flush();os.fsync(output.fileno())
        return receipt
    finally:os.close(lock)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('pack', 'receive', 'seed'))
    for name in ('repository', 'selection', 'history', 'captures', 'archive', 'directory'):
        parser.add_argument('--' + name, type=Path)
    parser.add_argument('--sha256')
    parser.add_argument('--node', choices=('node-a', 'node-b'))
    parser.add_argument('--run', action='store_true')
    a = parser.parse_args()
    if not a.run:
        print('PLAN_ONLY_NO_WRITES'); return
    need(os.name == 'posix' and os.getuid() == os.geteuid() == 1204, 'Use ordinary jwk')
    os.umask(0o077)
    if a.mode == 'pack':
        result = pack(a.repository, a.selection, a.history, a.captures, a.archive)
        print(json.dumps({'status': 'NATIVE_FOUR_PRIVATE_ARCHIVE_READY', 'templateCount': len(result['templates'])}))
    elif a.mode == 'receive':
        result = receive(a.archive, a.sha256, a.directory)
        print(json.dumps({'status': 'NATIVE_FOUR_PRIVATE_ARCHIVE_RECEIVED', 'templateCount': len(result['templates'])}))
    else:
        print(json.dumps(seed(a.directory, a.node)))


if __name__ == '__main__':
    main()
