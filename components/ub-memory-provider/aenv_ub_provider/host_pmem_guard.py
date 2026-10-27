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
    absent = volume.get('phase') == 'local_volume_absent'
    created = True if absent and 'status' in volume else (None if absent else False)
    if (session.get('phase') != 'local_resources_released'
            or volume.get('phase') not in ('local_volume_absent','not_attempted')
            or mount.get('phase') not in ('mount_absent','not_attempted')
            or (created is False and mount.get('phase') != 'not_attempted')
            or (created is None and volume.get('absenceQueried') is not True)
            or session.get('sharedBackingReleaseAuthorized') is not False):
        raise ValueError('No complete local volume/mount/lease retirement')
    return {'version':1,'scope':'local-host-pmem','state':'released',
            'publication':session['publication'], 'source':session['source'],
            'bootId':session['bootId'], 'ownerUid':session['ownerUid'],
            'ownerPid':session['ownerPid'], 'ownerStartTicks':session['ownerStartTicks'],
            'volumeCreated':created,
            'creationOutcome':('created_and_retired' if created is True else
                               'not_attempted' if created is False else 'creation_unconfirmed_now_absent'),
            'volumeUuid':volume['uuid'] if absent else None,
            'volumeId':volume['status']['id'] if created is True else None,
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
              'sharedBackingReleaseAuthorized','volumeCreated','creationOutcome'}
    if (not isinstance(value,dict) or set(value)!=required
            or type(value['version']) is not int or value['version']!=1
            or value['scope']!='local-host-pmem' or value['state']!='released'
            or value['publication']!=publication_binding(manifest,source) or value['source']!=source
            or value['bootId']!=boot_id or value['ownerUid']!=owner_uid
            or value['ownerPid']!=owner_pid or value['ownerStartTicks']!=owner_ticks
            or value['mountAbsent'] is not True or value['localVolumeAbsent'] is not True
            or value['sharedBackingReleaseAuthorized'] is not False
            or (value['volumeCreated'] is not None and type(value['volumeCreated']) is not bool)):
        raise ValueError('Missing, stale or incomplete root Host pmem release receipt')
    if value['volumeCreated'] is False:
        if value['volumeId'] is not None or value['volumeUuid'] is not None or value['creationOutcome']!='not_attempted':
            raise ValueError('Never-created receipt must not carry a fabricated volume identity')
        return
    if value['volumeCreated'] is None:
        if value['volumeId'] is not None or value['creationOutcome']!='creation_unconfirmed_now_absent':
            raise ValueError('Unknown creation must carry exact queried absence, not a fabricated ID')
        from .host_pmem import identity
        identity(value['volumeUuid'])
        return
    if value['creationOutcome']!='created_and_retired':
        raise ValueError('Created volume outcome differs')
    if type(value['volumeId']) is not int or not 0<=value['volumeId']<2**32:
        raise ValueError('Invalid released volume identity')
    from .host_pmem import identity
    identity(value['volumeUuid'])


def read_root_receipt(path):
    """Read bounded, non-writable-by-owner SDK-user, root-issued evidence."""
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022
                or not 0<info.st_size<=65536):
            raise ValueError('Root Host pmem release receipt ownership/mode/size differs')
        data=stream.read(65537)
        if len(data)>65536:
            raise ValueError('Root release receipt too large')
    return json.loads(data)


def require_release(path, manifest, source):
    """Called before freezing/retiring the SDK owner; accepts root-owned bytes only."""
    value=read_root_receipt(path)
    ticks=Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19]
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    check_release(value,manifest,source,os.geteuid(),os.getpid(),ticks,boot)


def check_cancelled_reader(value,manifest,epochs):
    """A terminal peer cancellation is distinct from an SDK unmap receipt.

    Only the guarded experiment may opt in, pinning the peer's maintenance
    epoch before SDK allocation. The root coordinator validates the human-
    relayed peer result before issuing the local root-owned copy.
    """
    required={'version','scope','state','ownerId','manifestSha256','readerId','epoch',
              'sdkImportAttempted','terminal'}
    expected='sha256:'+hashlib.sha256(contract.canonical(manifest)).hexdigest()
    if (not isinstance(value,dict) or set(value)!=required or type(value['version']) is not int
            or value['version']!=1 or value['scope']!='host-pmem-reader-cancel'
            or value['state']!='not_imported' or value['ownerId']!=manifest['ownerId']
            or value['manifestSha256']!=expected or value['readerId'] not in manifest['readers']
            or value['readerId'] not in epochs or value['epoch']!=epochs[value['readerId']]
            or value['sdkImportAttempted'] is not False or value['terminal'] is not True):
        raise ValueError('Invalid terminal pre-import cancellation; preserve publisher')
    return value['readerId']


def require_cancelled_reader(path,manifest,epochs):
    return check_cancelled_reader(read_root_receipt(path),manifest,epochs)
