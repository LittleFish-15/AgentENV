"""Separate test-file data cache from metadata in the new pmem block cache.

FIEMAP offsets are logical block-device offsets, not Host physical addresses.
Never use mincore of a DAX file to infer ordinary PageCache residency.
"""
import ctypes
import os
import stat
import struct


FIEMAP = 0xc020660b
HEADER = struct.Struct('=QQIIII')
EXTENT = struct.Struct('=5Q4I')
CAPACITY = 128


def data_ranges(buffer, length, device_bytes, page_size):
    if len(buffer)!=HEADER.size+CAPACITY*EXTENT.size:
        raise ValueError('Incomplete FIEMAP buffer')
    start, requested, flags, count, capacity, reserved = HEADER.unpack_from(buffer)
    if (start or requested != length or flags or reserved or capacity != CAPACITY
            or not 1 <= count <= capacity or len(buffer) != HEADER.size + capacity * EXTENT.size):
        raise ValueError('Incomplete FIEMAP header')
    result, cursor = [], 0
    for i in range(count):
        logical, physical, size, r0, r1, extent_flags, r2, r3, r4 = EXTENT.unpack_from(buffer, HEADER.size+i*EXTENT.size)
        if (logical != cursor or not size or physical % page_size or size % page_size
                or logical % page_size or physical+size > device_bytes or any((r0,r1,r2,r3,r4))
                or extent_flags & ~(1 | 0x1000) or (extent_flags & 1 and i != count-1)):
            raise ValueError('Sparse/unknown/unwritten/unaligned FIEMAP extent')
        used = min(size, length-cursor)
        if used <= 0:
            raise ValueError('FIEMAP returned extra extents')
        result.append((physical, used))
        cursor += size
    if cursor < length or not extent_flags & 1:
        raise ValueError('FIEMAP does not cover the complete file')
    return result


def count_residency(vector, ranges, page_size):
    pages=set()
    for offset,length in ranges:
        pages.update(range(offset//page_size,(offset+length+page_size-1)//page_size))
    if any(page>=len(vector) for page in pages):
        raise ValueError('File extent exceeds measured block-device mapping')
    total=sum(bool(value&1) for value in vector)*page_size
    data=sum(bool(vector[page]&1) for page in pages)*page_size
    return {'blockPageCacheBytes':total,'fileDataInBlockPageCacheBytes':data,
            'otherBlockPageCacheBytes':total-data,'fileDataExtentPages':len(pages)}


def collect(file_fd, length, volume):
    """Return unavailable on unsupported measurement instead of assuming zero."""
    import fcntl
    fd=None;address=None
    try:
        page=os.sysconf('SC_PAGE_SIZE')
        request=bytearray(HEADER.size+CAPACITY*EXTENT.size)
        HEADER.pack_into(request,0,0,length,0,0,CAPACITY,0)
        fcntl.ioctl(file_fd,FIEMAP,request,True)
        ranges=data_ranges(request,length,volume.bytes,page)
        fd=os.open('/dev/ubpmem_ro'+str(volume.id),os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        info=os.fstat(fd)
        if not stat.S_ISBLK(info.st_mode) or info.st_rdev!=os.makedev(volume.major,volume.minor):
            raise ValueError('Block cache measurement device differs')
        size=bytearray(8);fcntl.ioctl(fd,0x80081272,size,True)
        if struct.unpack('=Q',size)[0]!=volume.bytes:
            raise ValueError('Block device length changed')
        libc=ctypes.CDLL(None,use_errno=True)
        libc.statx.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_uint,ctypes.c_void_p]
        libc.statx.restype=ctypes.c_int
        attrs=ctypes.create_string_buffer(256)
        if libc.statx(fd,b'',0x1000,0x7ff,attrs):raise OSError(ctypes.get_errno(),'Block statx failed')
        bits=struct.unpack_from('=Q',attrs.raw,8)[0];supported=struct.unpack_from('=Q',attrs.raw,56)[0]
        if not supported&0x200000 or bits&0x200000:
            raise ValueError('Cannot interpret this block mapping mincore as ordinary PageCache')
        libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
        libc.mmap.restype=ctypes.c_void_p
        libc.mincore.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p];libc.mincore.restype=ctypes.c_int
        libc.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t];libc.munmap.restype=ctypes.c_int
        address=libc.mmap(None,volume.bytes,1,1,fd,0)
        if address==ctypes.c_void_p(-1).value:
            address=None;raise OSError(ctypes.get_errno(),'Block cache mmap failed')
        vector=(ctypes.c_ubyte*((volume.bytes+page-1)//page))()
        if libc.mincore(address,volume.bytes,vector):raise OSError(ctypes.get_errno(),'Block cache mincore failed')
        logical=0;file_ranges=[]
        for offset,size in ranges:
            file_ranges.append({'fileOffset':logical,'deviceOffset':offset,'bytes':size})
            logical+=size
        return {'state':'measured',**count_residency(vector,ranges,page),'fileDataRanges':file_ranges,
                'meaning':'ordinary block cache; data extents separated from other cached blocks'}
    except (OSError,ValueError) as error:
        return {'state':'unavailable','reason':str(error),'blockPageCacheBytes':None,
                'fileDataInBlockPageCacheBytes':None,'otherBlockPageCacheBytes':None}
    finally:
        if address is not None:libc.munmap(address,volume.bytes)
        if fd is not None:os.close(fd)
