"""Embedded into the fixed C demo. Never changes a device based on its number alone.

No udev rules, no ublk device creation/deletion, no existing daemon control.
The native child contains only GET_DEV_INFO. Any incompatible kernel fails closed.
"""
import threading


class ScopedDevicePermissions:
    def __init__(self, demo):
        self.demo=demo;self.stop_event=threading.Event();self.thread=None
        self.error=None;self.grants=[];self.rejected=set()
        self.protected={Path(row['path']).name for row in BASELINE_DEVICES}

    def query(self, number):
        result=command([str(ROOT/'ublk-owner-query'),str(number)],2)
        need(result.returncode==0,'Kernel UBLK GET_DEV_INFO failed; no device permissions granted')
        row=json.loads(result.stdout)
        need(set(row)=={'id','pid','uid','gid','state'} and row['id']==number,
             'Kernel device info contract differs; no permission changes')
        return row

    def authorized_process(self, row):
        if row['uid']!=1204 or row['gid']!=1205 or row['pid']<=0:return None
        process=Path('/proc')/str(row['pid'])
        try:
            start=ticks(row['pid'])
            uids=next(line.split()[1:] for line in (process/'status').read_text().splitlines() if line.startswith('Uid:'))
            if uids!=['1204']*4:return None
            groups=[line.split(':',2)[2] for line in (process/'cgroup').read_text().splitlines()]
            for variant in ('original','dax'):
                unit_row=self.demo.state['units'].get(variant)
                if not unit_row or unit_row.get('stopped'):continue
                if not any(group.endswith('/'+unit_row['name']) for group in groups):continue
                expected=PINS['artifacts/'+variant+'/bin/uvm-ublk-daemon']
                # Pin the actual executable inode via proc, not its printed path.
                h=hashlib.sha256()
                with (process/'exe').open('rb') as stream:
                    before=os.fstat(stream.fileno())
                    if not stat.S_ISREG(before.st_mode) or before.st_size>128*1024**2:return None
                    for raw in iter(lambda:stream.read(1024**2),b''):h.update(raw)
                    after=os.fstat(stream.fileno())
                if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):return None
                if h.hexdigest()!=expected:return None
                if ticks(row['pid'])!=start:return None
                return (variant,start)
        except (FileNotFoundError,ProcessLookupError):return None
        return None

    def consider(self, name):
        if name in self.protected:return
        path=Path('/dev')/name
        try:fd=os.open(path,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
        except FileNotFoundError:return
        try:
            st=os.fstat(fd)
            if not (stat.S_ISCHR(st.st_mode) if name.startswith('ublkc') else stat.S_ISBLK(st.st_mode)):return
            identity=(st.st_dev,st.st_ino,st.st_rdev)
            if identity in self.rejected:return
            if (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))==(1204,1205,0o600):return
            number=int(name[5:]);row=self.query(number)
            if row['uid']!=1204 or row['gid']!=1205:
                self.rejected.add(identity);return
            owner=self.authorized_process(row)
            if owner is None:return  # Not our Runtime; do not alter it.
            row2=self.query(number)
            if any(row2[key]!=row[key] for key in ('id','pid','uid','gid')):return
            if self.authorized_process(row2)!=owner:return
            current=path.lstat()
            if (current.st_dev,current.st_ino,current.st_rdev)!=identity:return
            event={'device':name,'inode':st.st_ino,'rdev':st.st_rdev,'owner':row2,
                   'variant':owner[0],'startTicks':owner[1],'permissionChangeIntent':True}
            # Durable permission intent precedes modification. O_PATH pins this inode:
            # deleting/reusing the pathname cannot retarget our chown/chmod to a new device.
            with (ROOT/'ublk-permissions.jsonl').open('a',encoding='utf-8') as stream:
                stream.write(json.dumps(event)+'\n');stream.flush();os.fsync(stream.fileno())
                pinned='/proc/self/fd/'+str(fd)
                os.chown(pinned,1204,1205);os.chmod(pinned,0o600)
                final=os.fstat(fd)
                need((final.st_uid,final.st_gid,stat.S_IMODE(final.st_mode))==(1204,1205,0o600),'Owned device permission update failed')
                event['permissionChangeAcknowledged']=True
                stream.write(json.dumps(event)+'\n');stream.flush();os.fsync(stream.fileno())
            self.grants.append(event)
        finally:os.close(fd)

    def run(self):
        try:
            while not self.stop_event.is_set():
                for name in ublk_devices():
                    if self.stop_event.is_set():break
                    self.consider(name)
                self.stop_event.wait(0.02)
        except BaseException as error:
            self.error=type(error).__name__+': '+str(error)

    def start(self):
        need(self.thread is None,'Permission monitor already started')
        verify_baseline(require_exact_inventory=True)
        need(checked([str(ROOT/'ublk-owner-query'),'--self-test']).strip()==b'UBLK_QUERY_ONLY_ABI_32_80','Query helper ABI self-check failed')
        # Test the target GET_INFO contract before any UB or Guest creation.
        for name in sorted(self.protected):
            if name.startswith('ublkc'):
                info=self.query(int(name[5:]))
                need(info['uid']==0 and info['pid']==BASELINE_OWNER['pid'],
                     'Target ownership contract differs from observed root holder; preserve all devices')
        self.thread=threading.Thread(target=self.run,name='hpc1-own-device-permissions',daemon=True)
        self.thread.start()

    def check(self):
        need(self.error is None,'Scoped device permission monitor stopped: '+str(self.error))

    def stop(self):
        if self.thread:
            self.stop_event.set();self.thread.join(5)
            need(not self.thread.is_alive(),'Permission monitor exit not confirmed')
        self.demo.state['ownedUblkPermissionGrants']=self.grants
        self.check()
