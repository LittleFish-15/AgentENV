"""Literal root supervisor additions for one original-only I/O-limit trial.

No user Python is imported by the root process. Candidate hashes are literal,
and the original executable must match the running service before activation.
"""
IO64_SERVER_SHA = '118fac40d567b07e236f6fcdff90bc8b8aa99bf2c1ae0e7998c7b608726d0517'
IO64_DAEMON_SHA = '3d6af078dc4b4ce5ad8531cfb1cb91242745bbfd300757a3197cce45e64cb3d0'


def io64_config(raw, candidate):
    text = raw.decode()
    require('rootfs_max_io_kib' not in text, 'Existing rootfs I/O setting')
    require(not re.search(r'(?m)^\s*\[ublk\.overlaybd\]\s*$', text), 'Existing overlaybd table needs explicit review')
    pattern = r'(?m)^daemon_binary_path\s*=\s*"([^"]+)"\s*$'
    matches = list(re.finditer(pattern, text))
    require(len(matches) == 1 and matches[0][1] == str(BASE/'bin/uvm-ublk-daemon'), 'Unexpected original daemon setting')
    return (re.sub(pattern, lambda _: 'daemon_binary_path = '+json.dumps(str(candidate)), text)
            + '\n[ublk.overlaybd]\nrootfs_max_io_kib = 64\n').encode()


def io64_meta(path):
    s = path.stat()
    require(stat.S_ISREG(s.st_mode), 'Expected regular executable')
    return {'dev': s.st_dev, 'inode': s.st_ino, 'uid': s.st_uid, 'gid': s.st_gid,
            'mode': stat.S_IMODE(s.st_mode), 'bytes': s.st_size}


def io64_verify_original(plan, path):
    require(io64_meta(path) == plan['original_server_metadata'], 'Original server metadata/inode changed')
    require(hashlib.sha256(scoped_read(path,256*1024**2)).hexdigest() == plan['original_server_sha256'], 'Original server bytes changed')


def io64_server_preflight(plan, before):
    installed = BASE/'bin/server'
    backup = Path(plan['original_server_backup'])
    candidate = Path(plan['server_candidate'])
    require(backup == Path(plan['work'])/'server.original', 'Backup outside experiment')
    require(candidate == Path(plan['work'])/'observer/server-rootfs-io64', 'Server candidate outside experiment')
    require(plan['server_sha256'] == IO64_SERVER_SHA and plan['candidate_sha256'] == IO64_DAEMON_SHA, 'Candidate pins changed')
    io64_verify_original(plan,installed)
    io64_verify_original(plan,backup)
    executable = Path('/proc')/before['MainPID']/'exe'
    a=executable.stat();b=installed.stat()
    require((a.st_dev,a.st_ino)==(b.st_dev,b.st_ino), 'Running original server is not installed inode')
    require(hashlib.sha256(scoped_read(candidate,256*1024**2)).hexdigest()==IO64_SERVER_SHA, 'Server candidate bytes differ')


def io64_install_server(plan, report):
    installed=BASE/'bin/server';backup=Path(plan['original_server_backup'])
    io64_verify_original(plan,installed);io64_verify_original(plan,backup)
    payload=scoped_read(Path(plan['server_candidate']),256*1024**2)
    require(hashlib.sha256(payload).hexdigest()==IO64_SERVER_SHA, 'Server candidate changed')
    temporary=installed.with_name('server.io64-new-'+plan['run_id'])
    meta=plan['original_server_metadata']
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(payload);f.flush();os.fchown(f.fileno(),meta['uid'],meta['gid']);os.fchmod(f.fileno(),meta['mode']);os.fsync(f.fileno())
    io64_verify_original(plan,installed)
    report['server_replacement_requested']=True
    os.replace(temporary,installed)
    require(hashlib.sha256(scoped_read(installed,256*1024**2)).hexdigest()==IO64_SERVER_SHA, 'Installed candidate differs')
    report['candidate_server_installed']=True
    report['installed_candidate_metadata']=io64_meta(installed)


def io64_active_server(plan, active):
    installed=BASE/'bin/server'
    a=(Path('/proc')/active['MainPID']/'exe').stat();b=installed.stat()
    require((a.st_dev,a.st_ino)==(b.st_dev,b.st_ino), 'Active Runtime is not installed candidate inode')
    require(hashlib.sha256(scoped_read(installed,256*1024**2)).hexdigest()==IO64_SERVER_SHA, 'Active candidate bytes differ')


def io64_restore_server(plan, report):
    installed=BASE/'bin/server';backup=Path(plan['original_server_backup'])
    io64_verify_original(plan,backup)
    current=hashlib.sha256(scoped_read(installed,256*1024**2)).hexdigest()
    if current==IO64_SERVER_SHA:
        temporary=installed.with_name('server.io64-restore-'+plan['run_id'])
        # Hardlink restores the exact original inode, including its attributes.
        os.link(backup,temporary,follow_symlinks=False)
        io64_verify_original(plan,temporary)
        require(hashlib.sha256(scoped_read(installed,256*1024**2)).hexdigest()==IO64_SERVER_SHA, 'Server changed during restoration')
        os.replace(temporary,installed)
    else:
        require(current==plan['original_server_sha256'], 'Unknown server binary; preserve for recovery')
    io64_verify_original(plan,installed)
    report['original_server_bytes_and_metadata_restored']=True


def io64_device_limit(path, expected_kib):
    path=Path(path).resolve(strict=True)
    require(path.parent==Path('/dev') and re.fullmatch(r'ublkb[0-9]+',path.name), 'Unexpected device path')
    s=path.stat();require(stat.S_ISBLK(s.st_mode),'Expected ublk block device')
    system=Path('/sys/class/block')/path.name
    require((system/'dev').read_text().strip()==str(os.major(s.st_rdev))+':'+str(os.minor(s.st_rdev)), 'Device/sysfs identity mismatch')
    values={name:int((system/'queue'/name).read_text().strip()) for name in
            ('max_hw_sectors_kb','max_sectors_kb','logical_block_size','physical_block_size','read_ahead_kb')}
    require(values['max_hw_sectors_kb']==expected_kib and values['max_sectors_kb']==expected_kib, 'Effective I/O limit differs for '+str(path)+': '+str(values))
    return {'device':str(path),'major':os.major(s.st_rdev),'minor':os.minor(s.st_rdev),'expected_kib':expected_kib,**values}


def io64_bound_devices(b):
    rootdev=(b['cwd']/'user-rootfs').resolve(strict=True)
    flags=rootfs_fd_flags(b['pid'],rootdev)
    require(flags, 'Rootfs device is not open in bound Guest')
    return {'rootfs':io64_device_limit(rootdev,64),
            'memory':io64_device_limit(b['memory_device'],256),'rootfs_fd_flags':flags}
