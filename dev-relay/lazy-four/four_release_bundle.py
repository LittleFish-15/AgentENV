"""Pack/receive coordinated build inputs without copying live Runtime state.

Run as the ordinary experiment user. This performs no network transfer, service
operation, SDK call or Guest action. The caller transfers the archive and its
SHA256 by the already available channel. No archive member is executed here.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile

CORE = '32ce41c0ac6436198860f888e07ef9793e58dc40'
TREE = '0e973a6e101c1a1c71b48bf70f2d910f48cd672f'
POLICY = 'afa4de05b17b89dec5c9a8f03b4852f836b45b28c76f6bdde812bd84ede2af00'
BINARIES = ('server','aenv','uvm-ublk-daemon','aenv-native-fd-verify','firecracker')
MEMBERS = {'build-receipt.json','tools-receipt.json','tools.ext4'} | {'artifacts/' + name for name in BINARIES}
ROOT = Path('/home/jwk/agent')
LIMIT = 3 * 1024**3


def need(ok, message):
    if not ok:
        raise ValueError(message)


def stamp(s):
    return (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)


def scoped(path, existing=True):
    path = Path(path)
    need(path.is_absolute() and path.is_relative_to(ROOT) and path.resolve(strict=existing) == path,
         'Path must remain in the experiment root without redirects')
    return path


def opened(path, limit):
    path = scoped(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        meta = os.fstat(fd)
        need(stat.S_ISREG(meta.st_mode) and meta.st_uid == os.getuid() and meta.st_nlink == 1
             and 0 < meta.st_size <= limit, 'Unexpected input type, owner, links or length')
        return os.fdopen(fd, 'rb'), meta
    except BaseException:
        os.close(fd)
        raise


def read_json(path):
    stream, before = opened(path, 2 * 1024**2)
    with stream:
        value = stream.read(before.st_size + 1)
        need(len(value) == before.st_size and stamp(before) == stamp(os.fstat(stream.fileno())), 'Metadata changed')
    return json.loads(value)


def digest_stream(stream, length, destination=None):
    h = hashlib.sha256()
    left = length
    while left:
        block = stream.read(min(left, 1024**2))
        need(bool(block), 'Short payload')
        left -= len(block)
        h.update(block)
        if destination:
            destination.write(block)
    need(not stream.read(1), 'Payload exceeds declared length')
    return h.hexdigest()


def validate_manifest(value):
    need(set(value) == {'version','coreCommit','coreTree','files'} and type(value['version']) is int
         and value['version'] == 1 and value['coreCommit'] == CORE and value['coreTree'] == TREE,
         'Bundle release identity differs')
    files = value['files']
    need(isinstance(files, dict) and set(files) == MEMBERS, 'Bundle file inventory differs')
    for name, row in files.items():
        need(set(row) == {'bytes','sha256'} and type(row['bytes']) is int
             and 0 < row['bytes'] <= 512 * 1024**2 and re.fullmatch('[0-9a-f]{64}', row['sha256']),
             'Invalid bounded file descriptor: ' + name)
    need(sum(row['bytes'] for row in files.values()) <= LIMIT, 'Bundle exceeds explicit budget')
    return files


def selected_inputs(build_path, tools_path):
    build, tools = read_json(build_path), read_json(tools_path)
    release = build.get('release', {})
    need(build.get('status') == 'COORDINATED_CANDIDATE_BINARIES_BUILT_NOT_DEPLOYED'
         and release.get('published') is True and release.get('coreCommit') == CORE
         and release.get('tree') == TREE and build.get('embeddedPolicySha256') == POLICY,
         'Coordinated build receipt is not complete')
    need(set(build.get('artifacts', {})) == set(BINARIES), 'All five coordinated binaries required')
    need(tools.get('status') == 'EXISTING_SNAPSHOT_TOOLS_VERIFIED_NO_IMAGE_CHANGE'
         and tools.get('mode') == 'runtime' and tools.get('originalUnchanged') is True
         and tools.get('lowerFilesystem') == 'ext4', 'Runtime ext4 tools receipt required')
    inputs, files = {}, {}
    for name in BINARIES:
        row = build['artifacts'][name]
        path = Path(build_path).parent / 'artifacts' / name
        need(Path(row['path']) == path, 'Pack only original staged build artifacts')
        inputs['artifacts/' + name] = path
        files['artifacts/' + name] = {'bytes':row['bytes'],'sha256':row['sha256']}
    inputs['tools.ext4'] = Path(tools['imagePath'])
    stream, meta = opened(inputs['tools.ext4'], 512 * 1024**2)
    stream.close()
    files['tools.ext4'] = {'bytes':meta.st_size,'sha256':tools['image']['sha256']}
    # Keep only the build/tool contracts, not logs, images, keys, source DBs or
    # unrelated fields that a future receipt version could add.
    build_receipt = {k:build[k] for k in ('status','embeddedPolicySha256')}
    build_receipt['release'] = {k:release[k] for k in ('published','coreCommit','tree')}
    build_receipt['artifacts'] = {n:{k:build['artifacts'][n][k] for k in ('path','bytes','sha256')} for n in BINARIES}
    tools_receipt = {k:tools[k] for k in ('status','mode','originalUnchanged','lowerFilesystem','toolsVersion','imagePath')}
    tools_receipt['image'] = {'sha256':tools['image']['sha256']}
    receipts = {'build-receipt.json':build_receipt,'tools-receipt.json':tools_receipt}
    for name, value in receipts.items():
        data = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
        inputs[name] = data
        files[name] = {'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
    manifest = {'version':1,'coreCommit':CORE,'coreTree':TREE,'files':files}
    validate_manifest(manifest)
    return inputs, manifest


def pack(build_path, tools_path, archive_path):
    inputs, manifest = selected_inputs(build_path, tools_path)
    archive_path = scoped(archive_path, False)
    need(archive_path.parent.is_dir() and not archive_path.exists(), 'New archive path required')
    with archive_path.open('xb') as output, tarfile.open(fileobj=output, mode='w') as archive:
        data = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
        info = tarfile.TarInfo('manifest.json');info.size=len(data);info.mode=0o600
        archive.addfile(info, io.BytesIO(data))
        for name, item in inputs.items():
            row = manifest['files'][name]
            info = tarfile.TarInfo(name);info.size=row['bytes'];info.mode=0o600
            if isinstance(item, bytes):
                archive.addfile(info, io.BytesIO(item))
                continue
            stream, before = opened(item, 512 * 1024**2)
            with stream:
                need(before.st_size == row['bytes'], 'Input size changed')
                h = hashlib.sha256()
                class Reader:
                    def read(self, size):
                        block = stream.read(size);h.update(block);return block
                archive.addfile(info, Reader())
                need(not stream.read(1) and stamp(before) == stamp(os.fstat(stream.fileno())), 'Input changed while packing')
                need(h.hexdigest() == row['sha256'], 'Source SHA256 differs: ' + name)
    stream, meta = opened(archive_path, LIMIT + 1024**2)
    with stream:
        pin = digest_stream(stream, meta.st_size)
    return {'status':'RELEASE_INPUT_BUNDLE_PACKED_NOT_TRANSFERRED','path':str(archive_path),'bytes':meta.st_size,
            'sha256':pin,'coreCommit':CORE,'includesGuestRootfsLayers':False,
            'includesUBPublication':False,'includesCredentials':False,'targetExecuted':False}


def inspect_archive(archive):
    members = []
    for member in archive:
        members.append(member)
        need(len(members) <= len(MEMBERS) + 1, 'Too many archive members')
    need(len(members) == len(MEMBERS) + 1 and len({m.name for m in members}) == len(members), 'Duplicate or unexpected archive members')
    need(set(m.name for m in members) == MEMBERS | {'manifest.json'} and all(m.isfile() and not m.issparse() for m in members),
         'Only exact regular bundle members accepted')
    manifest_member = archive.getmember('manifest.json')
    need(0 < manifest_member.size <= 65536, 'Manifest exceeds bound')
    manifest = json.load(archive.extractfile(manifest_member))
    files = validate_manifest(manifest)
    need(all(archive.getmember(name).size == row['bytes'] for name, row in files.items()), 'Tar lengths differ from manifest')
    return manifest


def receive(archive_path, expected_sha, destination):
    need(re.fullmatch('[0-9a-f]{64}', expected_sha) is not None, 'Explicit transfer SHA256 required')
    stream, before = opened(archive_path, LIMIT + 1024**2)
    with stream:
        need(digest_stream(stream, before.st_size) == expected_sha, 'Transferred archive SHA256 differs')
        stream.seek(0)
        with tarfile.open(fileobj=stream, mode='r:') as archive:
            manifest = inspect_archive(archive)
            destination = scoped(destination, False)
            need(destination.parent.is_dir() and not destination.exists() and not destination.is_symlink(), 'Fresh bundle destination required')
            destination.mkdir(mode=0o700)
            (destination / 'artifacts').mkdir(mode=0o700)
            for name, row in manifest['files'].items():
                path = destination / name
                with archive.extractfile(name) as source, path.open('xb') as target:
                    need(digest_stream(source,row['bytes'],target) == row['sha256'], 'Bundle member SHA256 differs: ' + name)
                    target.flush();os.fsync(target.fileno())
                path.chmod(0o700 if name.startswith('artifacts/') else 0o600)
            need(stamp(before) == stamp(os.fstat(stream.fileno())), 'Archive changed while receiving')
    receipt={'status':'COORDINATED_RELEASE_INPUTS_RECEIVED_NOT_DEPLOYED','coreCommit':CORE,
             'archiveSha256':expected_sha,'buildReport':str(destination/'build-receipt.json'),
             'toolsReport':str(destination/'tools-receipt.json'),'toolsImage':str(destination/'tools.ext4'),
             'includesGuestRootfsLayers':False,'includesUBPublication':False,'servicesChanged':False}
    with (destination/'received.json').open('x') as target:json.dump(receipt,target,indent=2)
    return receipt


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='operation',required=True)
    p=sub.add_parser('pack');p.add_argument('--build-report',required=True,type=Path);p.add_argument('--tools-report',required=True,type=Path);p.add_argument('--archive',required=True,type=Path)
    p=sub.add_parser('receive');p.add_argument('--archive',required=True,type=Path);p.add_argument('--sha256',required=True);p.add_argument('--destination',required=True,type=Path)
    for p in sub.choices.values():p.add_argument('--run',action='store_true')
    args=parser.parse_args()
    if not args.run:
        print(json.dumps({'status':'PLAN_ONLY','operation':args.operation,'SDK_called':False,'servicesChanged':False}));return 0
    need(os.name=='posix' and os.getuid()==os.geteuid()==1204 and os.getgid()==os.getegid()==1205,'Use ordinary experiment user')
    fields=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    need(all(int(fields[k].strip(),16)==0 for k in ('CapInh','CapPrm','CapEff','CapAmb')),'Zero capabilities required')
    os.umask(0o077)
    result=pack(args.build_report,args.tools_report,args.archive) if args.operation=='pack' else receive(args.archive,args.sha256,args.destination)
    print(json.dumps(result,indent=2));return 0


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'status':'STOPPED_BUNDLE_PRESERVE_INPUTS_AND_PARTIAL_OUTPUT','errorType':type(error).__name__,
                          'reason':str(error)[:1000],'SDK_called':False,'servicesChanged':False},indent=2));raise SystemExit(1)
