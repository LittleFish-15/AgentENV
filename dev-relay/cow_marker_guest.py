"""Guest-only deterministic RAM/rootfs marker, captured as a live process.

No Host service, device, permission or network operation. The Host launcher
places this only inside its own sandbox and invokes it through aenv exec.
"""
import ctypes
import hashlib
import json
import mmap
import os
from pathlib import Path
import re
import socket
import stat
import struct
import sys

ARENA_BYTES=16*1024**2
SEGMENT_BYTES=4*1024**2
FILE_BYTES=4*1024**2
CHUNK_BYTES=65536


def pattern(seed,label,index):
    return hashlib.shake_256((seed+'|'+label+'|'+str(index)).encode()).digest(CHUNK_BYTES)


def expected_hash(seed,label,start,length):
    digest=hashlib.sha256()
    for index in range(start//CHUNK_BYTES,(start+length)//CHUNK_BYTES):digest.update(pattern(seed,label,index))
    return digest.hexdigest()


class Marker:
    def __init__(self,base,seed):
        self.base=base;self.seed=seed;self.page=os.sysconf('SC_PAGESIZE')
        self.arena=mmap.mmap(-1,ARENA_BYTES,flags=mmap.MAP_PRIVATE|mmap.MAP_ANONYMOUS,
                             prot=mmap.PROT_READ|mmap.PROT_WRITE)
        self.address=ctypes.addressof(ctypes.c_char.from_buffer(self.arena))
        if self.address%self.page:raise RuntimeError('Arena is not page aligned')
        self.tags=['ram-base']*4
        for segment in range(4):self.fill_ram(segment,'ram-base')
        self.file=base/'rootfs.bin'
        with self.file.open('xb') as f:
            for index in range(FILE_BYTES//CHUNK_BYTES):f.write(pattern(seed,'rootfs-base',index))
            f.flush();os.fsync(f.fileno())
        meta=self.file.stat();self.file_identity=(meta.st_dev,meta.st_ino)
        self.file_tag='rootfs-base'

    def fill_ram(self,segment,label):
        start=segment*SEGMENT_BYTES
        for offset in range(start,start+SEGMENT_BYTES,CHUNK_BYTES):
            self.arena[offset:offset+CHUNK_BYTES]=pattern(self.seed,label,offset//CHUNK_BYTES)
        self.tags[segment]=label

    def fill_file(self,label):
        fd=os.open(self.file,os.O_RDWR|os.O_NOFOLLOW)
        with os.fdopen(fd,'r+b') as f:
            m=os.fstat(f.fileno())
            if not stat.S_ISREG(m.st_mode) or (m.st_dev,m.st_ino)!=self.file_identity or m.st_size!=FILE_BYTES:
                raise RuntimeError('Marker file identity changed')
            for index in range(FILE_BYTES//CHUNK_BYTES):f.write(pattern(self.seed,label,index))
            f.flush();os.fsync(f.fileno())
        self.file_tag=label

    def status(self):
        view=memoryview(self.arena)
        try:
            ram_hashes=[hashlib.sha256(view[i*SEGMENT_BYTES:(i+1)*SEGMENT_BYTES]).hexdigest() for i in range(4)]
        finally:view.release()
        expected=[expected_hash(self.seed,self.tags[i],i*SEGMENT_BYTES,SEGMENT_BYTES) for i in range(4)]
        fd=os.open(self.file,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as f:
            m=os.fstat(f.fileno())
            if (m.st_dev,m.st_ino)!=self.file_identity or m.st_size!=FILE_BYTES:raise RuntimeError('Marker file changed')
            digest=hashlib.sha256()
            for block in iter(lambda:f.read(CHUNK_BYTES),b''):digest.update(block)
        result={'version':1,'seed':self.seed,'server_pid':os.getpid(),'guest_uid':os.getuid(),
                'arena_bytes':ARENA_BYTES,'segment_bytes':SEGMENT_BYTES,'rootfs_file_bytes':FILE_BYTES,
                'guest_page_bytes':self.page,'arena_guest_virtual_address':self.address,
                'ram_tags':self.tags.copy(),'ram_hashes':ram_hashes,'rootfs_tag':self.file_tag,
                'rootfs_hash':digest.hexdigest(),
                'content_verified':ram_hashes==expected and digest.hexdigest()==expected_hash(self.seed,self.file_tag,0,FILE_BYTES)}
        try:
            cap=re.search(r'^CapEff:\s*([0-9a-fA-F]+)$',Path('/proc/self/status').read_text(),re.M)
            result['guest_effective_capabilities']=int(cap[1],16) if cap else None
        except OSError:result['guest_effective_capabilities']=None
        try:
            pages=ARENA_BYTES//self.page
            with open('/proc/self/pagemap','rb',buffering=0) as f:
                f.seek(self.address//self.page*8);raw=f.read(pages*8)
            if len(raw)!=pages*8:raise RuntimeError('Short Guest pagemap read')
            entries=[x[0] for x in struct.iter_unpack('=Q',raw)]
            present=sum(bool(x&(1<<63)) for x in entries)
            masked=sum(bool(x&(1<<63)) and (x&((1<<55)-1))==0 for x in entries)
            swapped=sum(bool(x&(1<<62)) for x in entries)
            result['guest_page_mapping']={'available':present==pages and masked==swapped==0,
                'present_pages':present,'masked_pages':masked,'swapped_pages':swapped,
                'guest_physical_addresses':[(x&((1<<55)-1))*self.page for x in entries] if present==pages and masked==swapped==0 else None}
        except Exception as e:
            result['guest_page_mapping']={'available':False,'error_type':type(e).__name__,'errno':getattr(e,'errno',None)}
        return result

    def operation(self,name):
        if name=='ram_a':self.fill_ram(0,'ram-a')
        elif name=='ram_b':self.fill_ram(1,'ram-b')
        elif name=='rootfs_a':self.fill_file('rootfs-a')
        elif name=='rootfs_b':self.fill_file('rootfs-b')
        elif name!='status':raise RuntimeError('Unknown marker operation')
        return self.status()


def receive(stream,limit):
    data=bytearray()
    while not data.endswith(b'\n'):
        block=stream.recv(min(65536,limit+1-len(data)))
        if not block:raise RuntimeError('Marker connection ended early')
        data.extend(block)
        if len(data)>limit:raise RuntimeError('Marker frame exceeds limit')
    return json.loads(data)


def serve(base,seed):
    marker=Marker(base,seed)
    server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    endpoint=base/'marker.sock'
    server.bind(str(endpoint));os.chmod(endpoint,0o600);server.listen(1);server.settimeout(10)
    (base/'ready.json').write_text(json.dumps({'seed':seed,'server_pid':os.getpid()}))
    # Lifetime is bounded by the Host sandbox TTL/own cleanup. Do not capture
    # an absolute Guest-clock expiry that could expire before a later restore.
    handled=0
    try:
        while handled<64:
            try:client,_=server.accept()
            except socket.timeout:continue
            handled+=1
            with client:
                client.settimeout(30)
                try:
                    request=receive(client,4096)
                    if request.get('seed')!=seed:raise RuntimeError('Marker identity differs')
                    response={'ok':True,'status':marker.operation(request.get('operation'))}
                except Exception as e:response={'ok':False,'error_type':type(e).__name__,
                                                'reason':str(e) if type(e) is RuntimeError else 'Marker operation failed'}
                client.sendall(json.dumps(response).encode()+b'\n')
    finally:
        server.close();marker.arena.close()


def request(base,seed,operation):
    client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    try:
        client.settimeout(30);client.connect(str(base/'marker.sock'))
        client.sendall(json.dumps({'seed':seed,'operation':operation}).encode()+b'\n')
        response=receive(client,1024**2)
    finally:client.close()
    print('BEGIN_COW_MARKER_STATUS');print(json.dumps(response));print('END_COW_MARKER_STATUS')
    if not response.get('ok'):raise SystemExit(1)


if __name__=='__main__':
    seed=sys.argv[2] if len(sys.argv)>2 else ''
    if re.fullmatch(r'[0-9a-f]{32}',seed) is None:raise SystemExit('Invalid test identity')
    base=Path('/pypika').resolve(strict=True)/('.aenv-cow-'+seed)
    if Path(__file__).resolve()!=base/'marker.py':raise SystemExit('Guest installation path required')
    if sys.argv[1]=='serve':serve(base,seed)
    elif sys.argv[1]=='request' and len(sys.argv)==4:request(base,seed,sys.argv[3])
    else:raise SystemExit('Unknown Guest marker mode')
