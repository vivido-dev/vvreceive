//! Linux implementation using /proc and rustix renameat_with.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use rustix::fs::{RenameFlags, renameat_with};
use vivid_protocol::file_drop::MAX_COMMITTED_PATH_BYTES;

pub fn open_shell_cwd(pid: u32) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(format!("/proc/{pid}/cwd"))
}

pub fn directory_path(directory: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()))
}

pub fn create_temporary_file(
    directory: &File,
    temporary_name: &str,
) -> io::Result<(File, Option<PathBuf>)> {
    let path = directory_path(directory).join(temporary_name);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    Ok((file, None))
}

pub fn remove_temporary_file(directory: &File, _dir_path: Option<&PathBuf>, temporary_name: &str) {
    let _ = std::fs::remove_file(directory_path(directory).join(temporary_name));
}

pub fn commit_temporary(
    directory: &File,
    temporary_name: &str,
    candidate_name: &str,
) -> io::Result<bool> {
    match renameat_with(
        directory.as_fd(),
        Path::new(temporary_name),
        directory.as_fd(),
        Path::new(candidate_name),
        RenameFlags::NOREPLACE,
    ) {
        Ok(()) => Ok(true),
        Err(error) if error == rustix::io::Errno::EXIST => Ok(false),
        Err(error) => Err(io::Error::from_raw_os_error(error.raw_os_error())),
    }
}

pub fn resolve_directory(directory: &File) -> Option<PathBuf> {
    let target = std::fs::read_link(directory_path(directory)).ok()?;
    let text = target.to_str()?;
    if !text.starts_with('/')
        || text.ends_with(" (deleted)")
        || text.len() >= MAX_COMMITTED_PATH_BYTES
        || text.chars().any(char::is_control)
        || text.split('/').any(|component| component == "..")
    {
        return None;
    }
    Some(target)
}

pub fn process_start_time(pid: u32) -> io::Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let end = stat
        .rfind(')')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid proc stat"))?;
    let mut fields = stat
        .get(end + 1..)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid proc stat"))?
        .split_ascii_whitespace();
    if matches!(fields.next(), Some("Z" | "X") | None) {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "login shell exited",
        ));
    }
    fields
        .nth(18)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "proc start time is absent"))?
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid proc start time"))
}

pub fn open_xdg_desktop() -> io::Result<File> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is unavailable"))?;
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| home.join(".config"))
        .join("user-dirs.dirs");
    let desktop = std::fs::read_to_string(config)
        .ok()
        .and_then(|content| {
            content.lines().find_map(|line| {
                let value = line.strip_prefix("XDG_DESKTOP_DIR=")?.trim();
                let value = value.strip_prefix('"')?.strip_suffix('"')?;
                Some(PathBuf::from(value.replace("$HOME", home.to_str()?)))
            })
        })
        .unwrap_or_else(|| home.join("Desktop"));
    if !desktop.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "XDG Desktop is not absolute",
        ));
    }
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(desktop)
}

#[allow(dead_code)]
pub fn open_desktop() -> io::Result<File> {
    open_xdg_desktop()
}
