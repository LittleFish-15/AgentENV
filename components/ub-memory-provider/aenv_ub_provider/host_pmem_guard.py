"""Bind root local-volume retirement to the SDK owner's exact publication."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from . import contract, raw


def publication_binding(manifest, source):
    if (set(manifest) != {'version','ownerId','mode','readers','replicas'}
            or type(manifest['version']) is not int or manifest['version'] != 1
            or manifest['mode'] != 'pmem' or not isinstance(manifest['ownerId'],str)
            or re.fullmatch('[0-9a-f]{32}',manifest['ownerId']) is None):
        raise ValueError('Expected exact native SDK publication manifest')
    contract.validate_spec(source)
    identity = {key:source[key] for key in ('objectId','generation','sha256','bytes')}
    matches = [replica for replica in manifest['replicas'] if replica.get('identity') == identity]
    if len(matches) != 1:
        raise ValueError('Source does not select exactly one SDK object')
    raw.validate_replica(matches[0], source)
    return {'ownerId':manifest['ownerId'],
            'manifestSha256':'sha256:'+hashlib.sha256(contract.canonical(manifest)).hexdigest(),
            'objectName':matches[0]['objectName']}


def release_record(session):
    volume, mount = session.get('volume',{}), session.get('mount',{})
    if (session.get('phase') != 'local_resources_released'
            or volume.get('phase') != 'local_volume_absent'
            or mount.get('phase') != 'mount_absent'
            or session.get('sharedBackingReleaseAuthorized') is not False):
        raise ValueError('No complete local volume/mount/lease retirement')
    return {'version':1,'scope':'local-host-pmem','state':'released',
            'publication':session['publication'], 'source':session['source'],
            'bootId':session['bootId'], 'ownerUid':session['ownerUid'],
            'ownerPid':session['ownerPid'], 'ownerStartTicks':session['ownerStartTicks'],
            'volumeUuid':volume['uuid'], 'volumeId':volume['status']['id'],
            'mountAbsent':True, 'localVolumeAbsent':True,
            'sharedBackingReleaseAuthorized':False}


def write_release(path, session):
    """Export a root-owned receipt readable by the ordinary SDK owner."""
    value = release_record(session)
    target = Path(path)
    parent = target.parent
    info = parent.stat()
    if (os.getuid() != 0 or os.geteuid() != 0 or not target.is_absolute()
            or parent.resolve(strict=True) != parent or info.st_uid != 0
            or not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022):
        raise ValueError('Release receipt requires a root-owned staging directory')
    encoded = contract.canonical(value)+b'\n'
    if target.exists() or target.is_symlink():
        fd = os.open(target,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o644
                    or info.st_size!=len(encoded) or stream.read(len(encoded)+1)!=encoded):
                raise ValueError('Existing root receipt differs or is incomplete; preserved')
        return value
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(encoded)
        stream.flush()
        os.fchmod(stream.fileno(),0o644)
        os.fsync(stream.fileno())
    fd = os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:os.fsync(fd)
    finally:os.close(fd)
    return value


def check_release(value, manifest, source, owner_uid, owner_pid, owner_ticks, boot_id):
    required={'version','scope','state','publication','source','bootId','ownerUid','ownerPid',
              'ownerStartTicks','volumeUuid','volumeId','mountAbsent','localVolumeAbsent',
              'sharedBackingReleaseAuthorized'}
    if (not isinstance(value,dict) or set(value)!=required
            or type(value['version']) is not int or value['version']!=1
            or value['scope']!='local-host-pmem' or value['state']!='released'
            or value['publication']!=publication_binding(manifest,source) or value['source']!=source
            or value['bootId']!=boot_id or value['ownerUid']!=owner_uid
            or value['ownerPid']!=owner_pid or value['ownerStartTicks']!=owner_ticks
            or value['mountAbsent'] is not True or value['localVolumeAbsent'] is not True
            or value['sharedBackingReleaseAuthorized'] is not False
            or type(value['volumeId']) is not int or not 0<=value['volumeId']<2**32):
        raise ValueError('Missing, stale or incomplete root Host pmem release receipt')
    from .host_pmem import identity
    identity(value['volumeUuid'])


def require_release(path, manifest, source):
    """Called before freezing/retiring the SDK owner; accepts root-owned bytes only."""
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022
                or not 0<info.st_size<=65536):
            raise ValueError('Root Host pmem release receipt ownership/mode/size differs')
        data=stream.read(65537)
        if len(data)>65536:
            raise ValueError('Root release receipt too large')
    ticks=Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19]
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    check_release(json.loads(data),manifest,source,os.geteuid(),os.getpid(),ticks,boot)
