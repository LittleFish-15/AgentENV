"""Prepare only the observation delta against the pinned original source."""
import hashlib, json, subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
REPO=HERE.parents[1]
BASE='ae9c62693839ce7effa2b45df31c0039ae4f9fbc'
def original(name):return subprocess.check_output(['git','show',BASE+':'+name],cwd=REPO)
def prepare(destination,rustfmt=None):
    changes={};metadata={}
    def change(name,fn):
        raw=original(name);text=raw.decode().replace('\r\n','\n');value=fn(text).encode()
        if value==text.encode():raise ValueError('Patch did not change '+name)
        changes[name]=value;metadata[name]={'before_sha256':hashlib.sha256(raw).hexdigest(),'after_sha256':hashlib.sha256(value).hexdigest()}
    def replace(text,old,new):
        if text.count(old)!=1:raise ValueError('Expected unique patch anchor: '+old[:80])
        return text.replace(old,new)
    change('storage/overlaybd/Cargo.toml',lambda s:replace(s,'[features]\n','[features]\nrootfs-read-trace = []\n'))
    change('storage/overlaybd/src/lib.rs',lambda s:s+'\n#[cfg(feature = "rootfs-read-trace")]\npub mod rootfs_access_trace;\n')
    def context(s):
        s=replace(s,"    ring: &'a AsyncIoRing,\n}","    ring: &'a AsyncIoRing,\n    #[cfg(feature = \"rootfs-read-trace\")]\n    source: Option<&'a std::path::Path>,\n}")
        s=replace(s,'        Self { ring }','        Self { ring, #[cfg(feature = "rootfs-read-trace")] source: None }')
        s=replace(s,"    pub fn ring(&self) -> &'a AsyncIoRing {",'''    pub fn with_read_source(self, source: &'a std::path::Path) -> Self {
        #[cfg(feature = "rootfs-read-trace")]
        { Self { source: Some(source), ..self } }
        #[cfg(not(feature = "rootfs-read-trace"))]
        { let _ = source; self }
    }

    #[cfg(feature = "rootfs-read-trace")]
    pub fn read_source(&self) -> Option<&'a std::path::Path> { self.source }

    pub fn ring(&self) -> &'a AsyncIoRing {''')
        s=replace(s,'        Box::pin(self.read_at(offset, len))','''        #[cfg(feature = "rootfs-read-trace")]
        if let Some(source) = _ctx.read_source() { crate::rootfs_access_trace::fallback(source); }
        Box::pin(self.read_at(offset, len))''')
        return s
    change('storage/overlaybd/src/io/virtual_file.rs',context)
    def local(s):
        for method,args,count in [('read_at_via','offset, len','data.len()'),('read_at_into_via','offset, dst','*data')]:
            old=f'        Box::pin(self.inner.{method}(ctx.ring(), {args}))'
            new=f'''        Box::pin(async move {{
            #[cfg(feature = "rootfs-read-trace")]
            let started = crate::rootfs_access_trace::now_ns();
            let result = self.inner.{method}(ctx.ring(), {args}).await;
            #[cfg(feature = "rootfs-read-trace")]
            if let (Some(source), Ok(data)) = (ctx.read_source(), &result) {{
                crate::rootfs_access_trace::record(source, &self.inner.file, &self.inner.path,
                    offset, {count}, self.inner.direct_io, started);
            }}
            result
        }})'''
            s=replace(s,old,new)
        return s
    change('storage/overlaybd/src/backend/local.rs',local)
    change('storage/ublk/src/impls/overlaybd_target.rs',lambda s:replace(s,'        let ctx = IoCtx::new(io_ring);','        let ctx = IoCtx::new(io_ring).with_read_source(&state.image_config_path);'))
    name='storage/overlaybd/src/rootfs_access_trace.rs';raw=(HERE/'rootfs_access_trace.rs').read_bytes();changes[name]=raw
    metadata[name]={'before_sha256':None,'after_sha256':hashlib.sha256(raw).hexdigest()}
    name='storage/overlaybd/examples/rootfs_access_calibration.rs';raw=(HERE/'calibration.rs').read_bytes();changes[name]=raw
    metadata[name]={'before_sha256':None,'after_sha256':hashlib.sha256(raw).hexdigest()}
    for name,raw in changes.items():
        p=destination/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
    if rustfmt:
        subprocess.run([str(rustfmt),'--edition','2021']+[str(destination/name) for name in (
            'storage/overlaybd/src/io/virtual_file.rs','storage/overlaybd/src/backend/local.rs','storage/ublk/src/impls/overlaybd_target.rs')],check=True)
        for name in changes:
            changes[name]=(destination/name).read_bytes();metadata[name]['after_sha256']=hashlib.sha256(changes[name]).hexdigest()
    (destination/'observation-patch.json').write_text(json.dumps({'base_commit':BASE,'changes':metadata},indent=2)+'\n',encoding='utf-8')
    return changes,metadata
if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('destination');p.add_argument('--rustfmt');a=p.parse_args();prepare(Path(a.destination),a.rustfmt)
