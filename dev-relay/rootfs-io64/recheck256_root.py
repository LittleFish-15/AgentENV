"""Read-only binary and device checks prepended to the original root supervisor."""
ORIGINAL_SERVER_SHA='0c5478b8382289c05ab1730401eea6918420c35594604cc7131592e81ad5aeff'


def verify_original_server(plan,state):
    installed=BASE/'bin/server';s=installed.stat()
    require(plan['original_server_sha256']==ORIGINAL_SERVER_SHA,'Unexpected original server pin')
    require(hashlib.sha256(scoped_read(installed,256*1024**2)).hexdigest()==ORIGINAL_SERVER_SHA,'Server is not byte-identical original')
    meta={'dev':s.st_dev,'inode':s.st_ino,'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'bytes':s.st_size}
    require(meta==plan['original_server_metadata'],'Original server metadata/inode changed')
    p=(Path('/proc')/state['MainPID']/'exe').stat()
    require((p.st_dev,p.st_ino)==(s.st_dev,s.st_ino),'Runtime executable is not original installed inode')


def original_device_limit(path):
    path=Path(path).resolve(strict=True)
    require(path.parent==Path('/dev') and re.fullmatch(r'ublkb[0-9]+',path.name),'Unexpected block-device path')
    s=path.stat();require(stat.S_ISBLK(s.st_mode),'Expected ublk block device')
    directory=Path('/sys/class/block')/path.name
    require((directory/'dev').read_text().strip()==str(os.major(s.st_rdev))+':'+str(os.minor(s.st_rdev)),'Device/sysfs identity mismatch')
    values={k:int((directory/'queue'/k).read_text().strip()) for k in
            ('max_hw_sectors_kb','max_sectors_kb','logical_block_size','physical_block_size','read_ahead_kb')}
    require(values['max_hw_sectors_kb']==values['max_sectors_kb']==256,'Original device is not effectively 256 KiB: '+str(path)+': '+str(values))
    return {'device':str(path),'major':os.major(s.st_rdev),'minor':os.minor(s.st_rdev),'expected_kib':256,**values}


def original_bound_limits(binding):
    rootdev=(binding['cwd']/'user-rootfs').resolve(strict=True)
    flags=rootfs_fd_flags(binding['pid'],rootdev)
    require(flags and all(f['O_DIRECT'] for f in flags),'Rootfs direct I/O differs from comparison trial')
    return {'rootfs':original_device_limit(rootdev),'memory':original_device_limit(binding['memory_device']),
            'rootfs_fd_flags':flags}
