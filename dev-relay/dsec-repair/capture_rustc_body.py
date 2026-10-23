#!/usr/bin/python3 -I
"""Capture the new server before this rustc wrapper releases Cargo's build lock.

The shared target/release/server name is not an artifact provenance boundary:
another build can replace it after Cargo exits. Capture the unique linked output
while Cargo is still waiting for this wrapper, preserving dependency-cache reuse.
"""
import hashlib,json,os,re,stat,subprocess,sys
from pathlib import Path
CONFIG={}

def need(value,reason):
    if not value:raise RuntimeError(reason)

def option(args,name):
    values=[]
    for index,arg in enumerate(args):
        if arg==name:
            need(index+1<len(args),'Missing compiler option value');values.append(args[index+1])
        elif arg.startswith(name+'='):values.append(arg[len(name)+1:])
    need(len(values)<=1,'Repeated compiler option '+name)
    return values[0] if values else None

def output_path(args,cfg,manifest_dir):
    if option(args,'--crate-name')!='server' or option(args,'--crate-type')!='bin':return None
    if Path(manifest_dir).resolve()!=Path(cfg['source']).resolve():return None
    need('link' in (option(args,'--emit') or '').split(','),'Server compiler call does not emit a linked binary')
    out=Path(option(args,'--out-dir') or '')
    need(out.resolve(strict=True)==Path(cfg['target']).resolve(strict=True)/'release/deps','Unexpected linked output directory')
    suffix=[]
    for index,arg in enumerate(args):
        value=args[index+1] if arg=='-C' and index+1<len(args) else arg[2:] if arg.startswith('-C') else ''
        if value.startswith('extra-filename='):suffix.append(value.split('=',1)[1])
    need(len(suffix)==1 and re.fullmatch('-[0-9a-f]{8,64}',suffix[0]),'Expected unique Cargo server output suffix')
    return out/('server'+suffix[0])

def capture(source,cfg):
    destination=Path(cfg['destination'])
    need(source.resolve(strict=True)==source and destination.parent.resolve(strict=True)==destination.parent,'Redirected artifact path')
    need(not destination.exists() and not destination.is_symlink(),'Prior captured artifact preserved')
    digest=hashlib.sha256();total=0;header=b''
    with source.open('rb') as stream,destination.open('xb') as out:
        before=os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and 0<before.st_size<=128*1024**2,'Unexpected linked server size')
        for block in iter(lambda:stream.read(1024**2),b''):
            if not header:header=block[:64]
            total+=len(block);need(total<=before.st_size,'Artifact grew while copying')
            digest.update(block);out.write(block)
        after=os.fstat(stream.fileno());out.flush();os.fsync(out.fileno())
    stamp=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    need(stamp(before)==stamp(after) and total==before.st_size,'Artifact changed while capturing')
    need(header[:6]==b'\x7fELF\x02\x01' and header[18:20]==b'\xb7\x00','Linked server is not AArch64 ELF')
    destination.chmod(0o750)
    result={'path':str(destination),'bytes':total,'sha256':digest.hexdigest(),
        'sourceManifest':str(Path(cfg['source'])/'Cargo.toml'),'linkedOutput':str(source),
        'capturedBeforeRustcWrapperExit':True}
    with Path(cfg['receipt']).open('x') as out:
        json.dump(result,out,indent=2);out.flush();os.fsync(out.fileno())
    return result

def main():
    args=sys.argv[1:];need(args and Path(args[0]).resolve(strict=True)==Path(CONFIG['rustc']).resolve(strict=True),'Unexpected Rust compiler')
    result=subprocess.run(args)
    if result.returncode:return result.returncode
    source=output_path(args[1:],CONFIG,os.environ.get('CARGO_MANIFEST_DIR',''))
    if source is not None:capture(source,CONFIG)
    return 0

if __name__=='__main__':raise SystemExit(main())
