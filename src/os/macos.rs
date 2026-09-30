//! macOS (Darwin) implementation using libproc, fcntl F_GETPATH, and renameatx_np.

use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io;
use std::mem::MaybeUninit;
use std::os::raw::{c_char, c_int};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;

use vivid_protocol::file_drop::MAX_COMMITTED_PATH_BYTES;

pub fn open_shell_cwd(pid: u32) -> io::Result<File> {
    let mut info = MaybeUninit::<sys::proc_vnodepathinfo>::uninit();
    let size = std::mem::size_of::<sys::proc_vnodepathinfo>() as c_int;
    let ret = unsafe {
        sys::proc_pidinfo(
            pid as c_int,
            sys::PROC_PIDVNODEPATHINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if ret != size {
        return if ret <= 0 {
            Err(io::Error::last_os_error())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid proc_vnodepathinfo size",
            ))
        };
    }
    let info = unsafe { info.assume_init() };
    let c_str = unsafe { CStr::from_ptr(info.pvi_cdir.vip_path.as_ptr()) };
    let path = c_str
        .to_str()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(path)
}

pub fn create_temporary_file(
    directory: &File,
    temporary_name: &str,
) -> io::Result<(File, Option<PathBuf>)> {
    let dir_path = resolve_directory(directory).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "destination directory cannot be resolved",
        )
    })?;
    let path = dir_path.join(temporary_name);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    Ok((file, Some(dir_path)))
}

pub fn remove_temporary_file(directory: &File, dir_path: Option<&PathBuf>, temporary_name: &str) {
    if let Some(path) = dir_path {
        let _ = std::fs::remove_file(path.join(temporary_name));
    } else if let Some(path) = resolve_directory(directory) {
        let _ = std::fs::remove_file(path.join(temporary_name));
    }
}

pub fn commit_temporary(
    directory: &File,
    temporary_name: &str,
    candidate_name: &str,
) -> io::Result<bool> {
    let dir_fd = directory.as_raw_fd();
    let c_temp = CString::new(temporary_name).map_err(io::Error::other)?;
    let c_cand = CString::new(candidate_name).map_err(io::Error::other)?;

    let ret = unsafe {
        sys::renameatx_np(
            dir_fd,
            c_temp.as_ptr(),
            dir_fd,
            c_cand.as_ptr(),
            sys::RENAME_EXCL,
        )
    };
    if ret == 0 {
        return Ok(true);
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EEXIST) {
        return Ok(false);
    }
    Err(err)
}

pub fn resolve_directory(directory: &File) -> Option<PathBuf> {
    let mut buf = [0_u8; libc::PATH_MAX as usize];
    let ret = unsafe {
        libc::fcntl(
            directory.as_raw_fd(),
            libc::F_GETPATH,
            buf.as_mut_ptr() as *mut c_char,
        )
    };
    if ret == -1 {
        return None;
    }
    let c_str = unsafe { CStr::from_ptr(buf.as_ptr() as *const c_char) };
    let text = c_str.to_str().ok()?;
    if !text.starts_with('/')
        || text.len() >= MAX_COMMITTED_PATH_BYTES
        || text.chars().any(char::is_control)
        || text.split('/').any(|component| component == "..")
    {
        return None;
    }
    use std::os::unix::fs::MetadataExt;
    let target_meta = std::fs::metadata(text).ok()?;
    let dir_meta = directory.metadata().ok()?;
    if target_meta.dev() != dir_meta.dev() || target_meta.ino() != dir_meta.ino() {
        return None;
    }
    Some(PathBuf::from(text))
}

pub fn process_start_time(pid: u32) -> io::Result<u64> {
    let mut info = MaybeUninit::<sys::proc_bsdinfo>::uninit();
    let size = std::mem::size_of::<sys::proc_bsdinfo>() as c_int;
    let ret = unsafe {
        sys::proc_pidinfo(
            pid as c_int,
            sys::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if ret != size {
        return if ret <= 0 {
            Err(io::Error::last_os_error())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid proc_bsdinfo size",
            ))
        };
    }
    let info = unsafe { info.assume_init() };
    if info.pbi_status == 4 {
        // Darwin SZOMB (4): process is a zombie / exited
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "login shell exited",
        ));
    }
    info.pbi_start_tvsec
        .checked_mul(1_000_000)
        .and_then(|seconds| seconds.checked_add(info.pbi_start_tvusec))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "proc start time overflow"))
}

pub fn open_macos_desktop() -> io::Result<File> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is unavailable"))?;
    let desktop = home.join("Desktop");
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(desktop)
}

#[allow(dead_code)]
pub fn open_desktop() -> io::Result<File> {
    open_macos_desktop()
}

#[allow(non_camel_case_types)]
mod sys {
    use std::os::raw::{c_char, c_int, c_longlong, c_uint, c_void};

    pub const PROC_PIDVNODEPATHINFO: c_int = 9;
    pub const PROC_PIDTBSDINFO: c_int = 3;
    pub const RENAME_EXCL: c_uint = 0x00000004;

    type gid_t = c_int;
    type off_t = c_longlong;
    type uid_t = c_int;
    type fsid_t = fsid;

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct fsid {
        pub val: [i32; 2usize],
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct vinfo_stat {
        pub vst_dev: u32,
        pub vst_mode: u16,
        pub vst_nlink: u16,
        pub vst_ino: u64,
        pub vst_uid: uid_t,
        pub vst_gid: gid_t,
        pub vst_atime: i64,
        pub vst_atimensec: i64,
        pub vst_mtime: i64,
        pub vst_mtimensec: i64,
        pub vst_ctime: i64,
        pub vst_ctimensec: i64,
        pub vst_birthtime: i64,
        pub vst_birthtimensec: i64,
        pub vst_size: off_t,
        pub vst_blocks: i64,
        pub vst_blksize: i32,
        pub vst_flags: u32,
        pub vst_gen: u32,
        pub vst_rdev: u32,
        pub vst_qspare: [i64; 2usize],
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct vnode_info {
        pub vi_stat: vinfo_stat,
        pub vi_type: c_int,
        pub vi_pad: c_int,
        pub vi_fsid: fsid_t,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct vnode_info_path {
        pub vip_vi: vnode_info,
        pub vip_path: [c_char; 1024usize],
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct proc_vnodepathinfo {
        pub pvi_cdir: vnode_info_path,
        pub pvi_rdir: vnode_info_path,
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct proc_bsdinfo {
        pub pbi_flags: u32,
        pub pbi_status: u32,
        pub pbi_xstatus: u32,
        pub pbi_pid: u32,
        pub pbi_ppid: u32,
        pub pbi_uid: u32,
        pub pbi_gid: u32,
        pub pbi_ruid: u32,
        pub pbi_rgid: u32,
        pub pbi_svuid: u32,
        pub pbi_svgid: u32,
        pub rfu_1: u32,
        pub pbi_comm: [u8; 16],
        pub pbi_name: [u8; 32],
        pub pbi_nfiles: u32,
        pub pbi_pgid: u32,
        pub pbi_pjobc: u32,
        pub e_tdev: u32,
        pub e_tpgid: u32,
        pub pbi_nice: i32,
        pub pbi_start_tvsec: u64,
        pub pbi_start_tvusec: u64,
    }

    unsafe extern "C" {
        pub fn proc_pidinfo(
            pid: c_int,
            flavor: c_int,
            arg: u64,
            buffer: *mut c_void,
            buffersize: c_int,
        ) -> c_int;

        pub fn renameatx_np(
            fromfd: c_int,
            from: *const c_char,
            tofd: c_int,
            to: *const c_char,
            flags: c_uint,
        ) -> c_int;
    }
}
