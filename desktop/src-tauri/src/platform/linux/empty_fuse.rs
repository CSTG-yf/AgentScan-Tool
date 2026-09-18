use std::ffi::OsStr;
use std::path::Path;
use std::time::{Duration, SystemTime};

use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry,
    ReplyOpen, Request,
};

const TTL: Duration = Duration::from_secs(1);
const ROOT_INODE: u64 = 1;
const EMPTY_INODE: u64 = 2;
const EMPTY_NAME: &str = "empty";

fn attr(inode: u64) -> FileAttr {
    let kind = if inode == ROOT_INODE {
        FileType::Directory
    } else {
        FileType::RegularFile
    };
    let permission = if inode == ROOT_INODE { 0o500 } else { 0o400 };
    FileAttr {
        ino: inode,
        size: 0,
        blocks: 0,
        atime: SystemTime::UNIX_EPOCH,
        mtime: SystemTime::UNIX_EPOCH,
        ctime: SystemTime::UNIX_EPOCH,
        crtime: SystemTime::UNIX_EPOCH,
        kind,
        perm: permission,
        nlink: if inode == ROOT_INODE { 2 } else { 1 },
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
        rdev: 0,
        blksize: 4096,
        flags: 0,
    }
}

struct EmptyFilesystem;

impl Filesystem for EmptyFilesystem {
    fn lookup(&mut self, _request: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        if parent == ROOT_INODE && name == OsStr::new(EMPTY_NAME) {
            reply.entry(&TTL, &attr(EMPTY_INODE), 0);
        } else {
            reply.error(libc::ENOENT);
        }
    }

    fn getattr(&mut self, _request: &Request<'_>, inode: u64, _fh: Option<u64>, reply: ReplyAttr) {
        if matches!(inode, ROOT_INODE | EMPTY_INODE) {
            reply.attr(&TTL, &attr(inode));
        } else {
            reply.error(libc::ENOENT);
        }
    }

    fn open(&mut self, _request: &Request<'_>, inode: u64, flags: i32, reply: ReplyOpen) {
        if inode != EMPTY_INODE {
            reply.error(libc::ENOENT);
        } else if flags & libc::O_ACCMODE != libc::O_RDONLY {
            reply.error(libc::EACCES);
        } else {
            reply.opened(0, fuser::consts::FOPEN_KEEP_CACHE);
        }
    }

    fn read(
        &mut self,
        _request: &Request<'_>,
        inode: u64,
        _fh: u64,
        _offset: i64,
        _size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        if inode == EMPTY_INODE {
            reply.data(&[]);
        } else {
            reply.error(libc::ENOENT);
        }
    }

    fn readdir(
        &mut self,
        _request: &Request<'_>,
        inode: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        if inode != ROOT_INODE {
            reply.error(libc::ENOTDIR);
            return;
        }
        let entries = [
            (ROOT_INODE, FileType::Directory, "."),
            (ROOT_INODE, FileType::Directory, ".."),
            (EMPTY_INODE, FileType::RegularFile, EMPTY_NAME),
        ];
        for (index, entry) in entries.iter().enumerate().skip(offset.max(0) as usize) {
            if reply.add(entry.0, (index + 1) as i64, entry.1, entry.2) {
                break;
            }
        }
        reply.ok();
    }
}

pub fn serve(mountpoint: &Path) -> Result<(), String> {
    fuser::mount2(
        EmptyFilesystem,
        mountpoint,
        &[
            MountOption::FSName("tracebastion-empty".to_owned()),
            MountOption::RO,
            MountOption::NoExec,
            MountOption::NoSuid,
            MountOption::NoDev,
        ],
    )
    .map_err(|error| format!("mount TraceBastion empty-file FUSE filesystem: {error}"))
}
