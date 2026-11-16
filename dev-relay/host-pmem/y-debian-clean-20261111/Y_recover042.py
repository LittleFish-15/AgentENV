"""Read a fixed part of the existing diagnostic archive; never repeat a test."""
import base64,hashlib,json,os,pathlib,platform,stat,sys
P=pathlib.Path
ARCHIVE=P('/home/jwk/aenv-y-clean-20261111/diagnosis-no-anchor-20261116-038/evidence.tar.gz')
SIZE=1021774
SHA='d117835140cfe8e710200f7ccbb54a08d40039b40c433f199f6ade8ba308f112'
EXPECTED={'hostname':'debian','machineId':'9c4987ac1e5849409b53b20724f12d34','bootId':'d005bda4-518d-4766-b704-259df7bae4f9','kernel':'6.6.122ublk+','architecture':'x86_64'}
def main():
 assert os.getuid()==os.geteuid()==0 and len(sys.argv)==2
 index=int(sys.argv[1]);assert str(index)==sys.argv[1] and index in (0,1)
 identity={'hostname':platform.node(),'machineId':P('/etc/machine-id').read_text().strip(),'bootId':P('/proc/sys/kernel/random/boot_id').read_text().strip(),'kernel':platform.release(),'architecture':platform.machine()};assert identity==EXPECTED
 assert ARCHIVE.resolve()==ARCHIVE and not ARCHIVE.is_symlink()
 fd=os.open(ARCHIVE,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 with os.fdopen(fd,'rb') as f:
  before=os.fstat(f.fileno());assert stat.S_ISREG(before.st_mode) and before.st_uid==0 and before.st_size==SIZE
  assert hashlib.file_digest(f,'sha256').hexdigest()==SHA
  offset=index*512000;size=min(512000,SIZE-offset);f.seek(offset);data=f.read(size);assert len(data)==size
  after=os.fstat(f.fileno());assert (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)
 value={'experiment':'Y_EVIDENCE_RECOVERY042','index':index,'offset':offset,'bytes':len(data),'partSha256':hashlib.sha256(data).hexdigest(),'dataBase64':base64.b64encode(data).decode(),'archiveBytes':SIZE,'archiveSha256':SHA,'readOnly':True,'XContacted':False}
 raw=json.dumps(value,separators=(',',':'));assert len(raw.encode())<700000;print(raw,flush=True)
if __name__=='__main__':main()
