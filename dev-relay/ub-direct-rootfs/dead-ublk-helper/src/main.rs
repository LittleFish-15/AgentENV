//! One reviewed A-node orphan only. No module loading, STOP, retry, or SDK.
use io_uring::{opcode::UringCmd80, squeue::Entry128, types, IoUring};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

const BOOT: &str = "58d0ee5f-f886-4eb6-93ea-a6328d14d139";
const DELETE_STARTED_NS: i128 = 1793065418082682480;

fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok { Ok(()) } else { Err(io::Error::other(message)) }
}

#[repr(C)]
union Command {
    data: [u8; 80],
    header: ublk_sys::ublksrv_ctrl_cmd,
}

fn command(ring: &mut IoUring<Entry128>, ctrl: &File, id: u32, op: u32,
           info: Option<&mut ublk_sys::ublksrv_ctrl_dev_info>) -> io::Result<()> {
    let mut header = ublk_sys::ublksrv_ctrl_cmd { dev_id: id, queue_id: u16::MAX, ..Default::default() };
    if let Some(info) = info {
        header.addr = info as *mut _ as u64;
        header.len = std::mem::size_of::<ublk_sys::ublksrv_ctrl_dev_info>() as u16;
    }
    let mut cmd = Command { data: [0; 80] }; cmd.header = header;
    // Same typed UAPI and SQE128 command as aenv UVMUblkCtrl. Buffer remains
    // alive until the single completion; an interrupted wait exits the process.
    let entry = UringCmd80::new(types::Fd(ctrl.as_raw_fd()), op)
        .cmd(unsafe { cmd.data }).build().user_data(1);
    unsafe { ring.submission().push(&entry) }.map_err(|_| io::Error::other("submission queue full"))?;
    if let Err(error) = ring.submit_and_wait(1) {
        eprintln!("uring wait failed; operation outcome unknown: {error}");
        std::process::exit(4); // Never return while kernel may retain info pointer.
    }
    let result = ring.completion().next().ok_or_else(|| io::Error::other("completion absent"))?;
    require(result.user_data() == 1, "completion identity differs")?;
    if result.result() < 0 { return Err(io::Error::from_raw_os_error(-result.result())); }
    require(result.result() == 0, "unexpected completion result")
}

fn device_identity(id: u32) -> io::Result<(u64, u64, i64, i64)> {
    require(id == 12 || id == 13, "only reviewed A devices 12 and 13 are permitted")?;
    require(!Path::new(&format!("/dev/ublkb{id}")).exists()
            && !Path::new(&format!("/sys/class/block/ublkb{id}")).exists(), "block device still present")?;
    let path = format!("/dev/ublkc{id}");
    let meta = fs::symlink_metadata(&path)?;
    require(meta.file_type().is_char_device() && libc::major(meta.rdev()) == 242
            && libc::minor(meta.rdev()) == id, "character device identity differs")?;
    let changed_ns = i128::from(meta.ctime()) * 1_000_000_000 + i128::from(meta.ctime_nsec());
    require(changed_ns > 0 && changed_ns < DELETE_STARTED_NS, "device changed since original failed DELETE")?;
    require(fs::read_to_string(format!("/sys/class/ublk-char/ublkc{id}/dev"))?.trim() == format!("242:{id}"),
            "sysfs device identity differs")?;
    Ok((meta.dev(), meta.ino(), meta.ctime(), meta.ctime_nsec()))
}

fn accepted(info: &ublk_sys::ublksrv_ctrl_dev_info, id: u32) -> bool {
    info.dev_id == id && (id == 12 || id == 13) && info.state == ublk_sys::UBLK_S_DEV_DEAD as u16
        && info.ublksrv_pid == -1 && info.owner_uid == 1204 && info.owner_gid == 1205
}

fn run() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    require(args.len() == 3 && (args[1] == "inspect" || args[1] == "delete-reviewed-dead"),
            "usage: inspect|delete-reviewed-dead 12|13")?;
    let id: u32 = args[2].parse().map_err(|_| io::Error::other("invalid device id"))?;
    require(unsafe { libc::getuid() } == 0 && unsafe { libc::geteuid() } == 0, "root required")?;
    require(fs::read_to_string("/proc/sys/kernel/hostname")?.trim() == "server1", "A/server1 only")?;
    require(fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim() == BOOT, "boot changed")?;
    for pid in [3966082, 3966531, 4070069] {
        require(!Path::new(&format!("/proc/{pid}")).exists(), "old PID present or reused; preserve state")?;
    }
    let identity = device_identity(id)?;
    let ctrl = OpenOptions::new().read(true).write(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/dev/ublk-control")?;
    require(ctrl.metadata()?.file_type().is_char_device(), "control is not a character device")?;
    let mut ring = IoUring::<Entry128>::builder().build(2)?;
    let mut info = ublk_sys::ublksrv_ctrl_dev_info::default();
    command(&mut ring, &ctrl, id, ublk_sys::UBLK_U_CMD_GET_DEV_INFO, Some(&mut info))?;
    println!("{{\"phase\":\"kernel-info\",\"id\":{},\"state\":{},\"serverPid\":{},\"uid\":{},\"gid\":{},\"flags\":{}}}",
        info.dev_id, info.state, info.ublksrv_pid, info.owner_uid, info.owner_gid, info.flags);
    require(accepted(&info, id), "kernel device is not the expected stopped ordinary-user device")?;
    require(device_identity(id)? == identity, "device incarnation changed during query")?;
    if args[1] == "delete-reviewed-dead" {
        println!("{{\"phase\":\"delete-intent\",\"id\":{id}}}");
        command(&mut ring, &ctrl, id, ublk_sys::UBLK_U_CMD_DEL_DEV, None)?;
        println!("{{\"phase\":\"delete-ack\",\"id\":{id}}}");
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() { eprintln!("STOP_PRESERVE: {error}"); std::process::exit(1); }
}
