"""OBMM Host read-only pmem ABI v1. No SDK allocation, mount or module loading.

The caller retains SDK anchors and serializes operations. Closing the control FD
does not destroy a volume. Local retirement never authorizes owner deallocation.
"""
from dataclasses import asdict, dataclass
import errno
import hashlib
import os
from pathlib import Path
import stat
import struct
import uuid


ABI = 1
MAX_SEGMENTS = 32
MAX_BYTES = 16 * 1024 ** 3
HEADER = struct.Struct('=II16s')
SEGMENT = struct.Struct('=iIQQ')
STATUS = struct.Struct('=II16sIIII7Q')
CREATE_BYTES = HEADER.size + MAX_SEGMENTS * SEGMENT.size
CREATE = (1 << 30) | (CREATE_BYTES << 16) | (0xb8 << 8)
QUERY = (3 << 30) | (STATUS.size << 16) | (0xb8 << 8) | 1
DESTROY = (1 << 30) | (STATUS.size << 16) | (0xb8 << 8) | 2


def identity(value):
    parsed = uuid.UUID(value)
    if str(parsed) != value or parsed.int == 0:
        raise ValueError('Expected canonical nonzero volume UUID')
    return parsed.bytes


@dataclass(frozen=True)
class Segment:
    fd: int
    offset: int
    bytes: int


@dataclass(frozen=True)
class VolumeStatus:
    uuid: str
    id: int
    state: int
    major: int
    minor: int
    bytes: int
    openers: int
    active_io: int
    block_reads: int
    block_bytes: int
    dax_accesses: int
    dax_span_bytes: int


def create_request(volume_uuid, segments, page_size):
    if (type(page_size) is not int or page_size < 4096 or page_size & (page_size - 1)
            or not 1 <= len(segments) <= MAX_SEGMENTS):
        raise ValueError('Invalid page size or segment count')
    request = bytearray(CREATE_BYTES)
    HEADER.pack_into(request, 0, ABI, len(segments), identity(volume_uuid))
    total = 0
    for i, segment in enumerate(segments):
        if (not isinstance(segment, Segment)
                or any(type(n) is not int for n in (segment.fd, segment.offset, segment.bytes))
                or not 0 <= segment.fd < 2 ** 31 or segment.offset < 0
                or not 0 < segment.bytes <= MAX_BYTES
                or segment.offset + segment.bytes >= 2 ** 64
                or segment.offset % page_size or segment.bytes % page_size):
            raise ValueError('Invalid or unaligned region segment')
        total += segment.bytes
        SEGMENT.pack_into(request, HEADER.size + i * SEGMENT.size,
                          segment.fd, 0, segment.offset, segment.bytes)
    if total > MAX_BYTES:
        raise ValueError('Volume exceeds kernel byte limit')
    return request


def status_request(volume_uuid, volume_id=0):
    if type(volume_id) is not int or not 0 <= volume_id < 2 ** 32:
        raise ValueError('Invalid volume ID')
    return bytearray(STATUS.pack(ABI, 0, identity(volume_uuid), volume_id, *([0] * 10)))


def parse_status(data, volume_uuid):
    if len(data) != STATUS.size:
        raise ValueError('Unexpected STATUS size')
    version, reserved, observed_uuid, *fields = STATUS.unpack(data)
    if version != ABI or reserved or observed_uuid != identity(volume_uuid):
        raise ValueError('STATUS ABI or UUID differs')
    result = VolumeStatus(volume_uuid, *fields)
    if result.state != 1 or result.major == 0 or not 0 < result.bytes <= MAX_BYTES:
        raise ValueError('Invalid serving volume status')
    return result


class Control:
    """Borrow an already opened control FD. Use open_control() for actual Linux."""
    def __init__(self, fd, ioctl=None, page_size=None):
        if ioctl is None:
            import fcntl
            ioctl = fcntl.ioctl
        self.fd, self.ioctl = fd, ioctl
        self.page_size = os.sysconf('SC_PAGE_SIZE') if page_size is None else page_size

    def validate_segments(self, segments):
        import fcntl
        for segment in segments:
            flags = fcntl.fcntl(segment.fd, fcntl.F_GETFL)
            if (flags & os.O_ACCMODE != os.O_RDONLY or flags & os.O_SYNC != os.O_SYNC
                    or not stat.S_ISCHR(os.fstat(segment.fd).st_mode)):
                raise ValueError('Expected readonly O_SYNC OBMM character FD')
        # The kernel additionally verifies OBMM fops, region type and attributes.

    def create(self, volume_uuid, segments):
        request = create_request(volume_uuid, segments, self.page_size)
        self.validate_segments(segments)
        self.ioctl(self.fd, CREATE, request, True)

    def query(self, volume_uuid):
        request = status_request(volume_uuid)
        self.ioctl(self.fd, QUERY, request, True)
        return parse_status(request, volume_uuid)

    def destroy(self, observed):
        self.ioctl(self.fd, DESTROY, status_request(observed.uuid, observed.id), True)


def open_control():
    """Return owned FD after checking the device against the registered misc dev."""
    fd = os.open('/dev/obmm_pmem', os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        observed = os.fstat(fd)
        major, minor = map(int, Path('/sys/class/misc/obmm_pmem/dev').read_text().strip().split(':'))
        if (not stat.S_ISCHR(observed.st_mode) or observed.st_uid != 0
                or stat.S_IMODE(observed.st_mode) != 0o600
                or observed.st_rdev != os.makedev(major, minor)):
            raise ValueError('Control device identity or permissions differ')
        return fd
    except BaseException:
        os.close(fd)
        raise


class LocalVolume:
    """One create attempt with durable intent and explicit local retirement.

    save(record) must durably persist a private transaction before returning.
    This in-process object is not an orphan recovery authority. On process loss,
    keep anchors/backing and reconcile the journal with the exact node/boot.
    """
    def __init__(self, control, save):
        self.control, self.save = control, save
        self.record = {'version': 1, 'uuid': str(uuid.uuid4()), 'phase': 'new',
                       'sharedBackingReleaseAuthorized': False}
        self.observed = None

    def mark(self, phase, **values):
        self.record.update(phase=phase, **values)
        self.save(dict(self.record))

    def create(self, segments):
        if self.record['phase'] != 'new':
            raise RuntimeError('Create already attempted; query the recorded UUID, never retry')
        # Validate shape before intent; never write process-relative FDs as a
        # reusable manifest. Caller separately journals UB object provenance.
        create_request(self.record['uuid'], segments, self.control.page_size)
        self.control.validate_segments(segments)
        self.mark('create_intent', bytes=sum(s.bytes for s in segments), segmentCount=len(segments))
        try:
            self.control.create(self.record['uuid'], segments)
        except BaseException as error:
            self.mark('create_unconfirmed', error=str(error), errno=getattr(error, 'errno', None),
                      regionSealsMayRemain=True)
            raise
        self.mark('create_acknowledged', regionSealsMayRemain=True)
        return self.confirm()

    def confirm(self):
        # EEXIST could identify somebody else's volume; do not adopt it.
        if (self.record['phase'] not in ('create_acknowledged', 'create_unconfirmed', 'query_unconfirmed')
                or self.record.get('errno') == errno.EEXIST):
            raise RuntimeError('No reconcilable own creation intent')
        try:
            observed = self.control.query(self.record['uuid'])
            if observed.bytes != self.record['bytes']:
                raise ValueError('Created volume length differs')
        except BaseException as error:
            self.mark('query_unconfirmed', queryError=str(error))
            raise
        self.observed = observed
        self.mark('serving', status=asdict(observed))
        return observed

    def retire(self):
        if self.record['phase'] not in ('serving', 'retire_busy') or self.observed is None:
            raise RuntimeError('Local volume identity is not confirmed')
        current = self.control.query(self.record['uuid'])
        if (current.id, current.major, current.minor, current.bytes) != (
                self.observed.id, self.observed.major, self.observed.minor, self.observed.bytes):
            raise RuntimeError('Volume changed; preserve resources')
        if current.openers or current.active_io:
            self.mark('retire_busy', status=asdict(current))
            raise RuntimeError('Mounted/open/busy volume; preserve anchors')
        self.mark('destroy_intent', status=asdict(current))
        try:
            self.control.destroy(current)
        except OSError as error:
            self.mark('retire_busy' if error.errno == errno.EBUSY else 'destroy_unconfirmed',
                      error=str(error), destroyErrno=error.errno)
            raise
        except BaseException as error:
            self.mark('destroy_unconfirmed', error=str(error))
            raise
        self.mark('destroy_acknowledged')
        self.confirm_absent()

    def confirm_absent(self):
        if self.record['phase'] not in ('destroy_intent', 'destroy_acknowledged', 'destroy_unconfirmed'):
            raise RuntimeError('No local destroy intent to reconcile')
        try:
            self.control.query(self.record['uuid'])
        except OSError as error:
            if error.errno != errno.ENOENT:
                raise
            self.mark('local_volume_absent', sharedBackingReleaseAuthorized=False)
            return
        raise RuntimeError('Volume still exists; preserve anchors, do not retry destroy blindly')


def verify_dax_file(control, volume, path, length, sha256):
    """Read a mounted test file from this exact local volume, with no fallback.

    Requires an already mounted, sealed publication held by the caller. This
    verifies the local DAX read path; it cannot attest cross-node provenance or
    savings. Offered DAX spans are not actual payload bytes or physical cost.
    """
    from . import fsdax
    if (type(length) is not int or not 0 < length <= volume.bytes
            or not isinstance(sha256, str) or len(sha256) != 64
            or any(c not in '0123456789abcdef' for c in sha256)):
        raise ValueError('Invalid expected DAX test-file identity')
    source = Path(path)
    if not source.is_absolute() or source.resolve(strict=True) != source:
        raise ValueError('DAX test path must be absolute without redirection')
    before = control.query(volume.uuid)
    stable_fields = ('uuid', 'id', 'major', 'minor', 'bytes')
    if any(getattr(before, key) != getattr(volume, key) for key in stable_fields):
        raise ValueError('Volume identity changed before test')
    fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        observed = fsdax.validate_fd(fd, length)
        if observed['device'] != os.makedev(volume.major, volume.minor):
            raise ValueError('DAX file is not on the requested pmem volume')
        digest, offset = hashlib.sha256(), 0
        while offset < length:
            fsdax.validate_fd(fd, length)
            count = min(1024 * 1024, length - offset)
            data = os.pread(fd, count, offset)
            if len(data) != count:
                raise OSError('Short DAX read; no cached fallback')
            digest.update(data)
            offset += count
        if digest.hexdigest() != sha256:
            raise ValueError('DAX file content differs')
        fsdax.validate_fd(fd, length)
        after = control.query(volume.uuid)
        if any(getattr(after, key) != getattr(volume, key) for key in stable_fields):
            raise ValueError('Volume identity changed during test')
        if after.dax_accesses <= before.dax_accesses or after.dax_span_bytes <= before.dax_span_bytes:
            raise ValueError('No positive DAX access evidence; sparse-only files are insufficient')
        # No write is issued even if this unexpectedly succeeds. A mere EACCES
        # is not proof that the mounted filesystem itself is read-only.
        try:
            writer = os.open(source, os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError as error:
            if error.errno != errno.EROFS:
                raise
        else:
            os.close(writer)
            raise RuntimeError('Unexpected writable open; no data was written')
        return {'state': 'local_dax_file_verified', 'volume': asdict(after), 'file': observed,
                'preadBytes': offset, 'sha256': digest.hexdigest(), 'writeOpenErrno': errno.EROFS,
                'daxAccessDelta': after.dax_accesses - before.dax_accesses,
                'daxOfferedSpanBytesDelta': after.dax_span_bytes - before.dax_span_bytes,
                'crossNodePhysicalIdentityAccepted': False, 'netSavingsBytes': None}
    finally:
        os.close(fd)
