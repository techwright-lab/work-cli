//! Fresh owned directory cursors; deliberately no clone/dup/from-raw constructor.

use std::ffi::CStr;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

/// A fresh independent native enumeration offset. Each census must open a new
/// cursor, not duplicate an existing FD (dup would share its offset).
///
/// This owns only the directory FD and closes it on drop. It does not prove the
/// held parent's route, actual mounted-volume identity, ACLs or access safety.
#[derive(Debug)]
pub struct DirectoryCursor(OwnedFd);

impl DirectoryCursor {
    /// One directory-only, no-follow openat of a validated single component.
    /// No retries, fallback, descriptor duplication or readable payload open.
    /// The parent is borrowed only during acquisition. Concurrent topology can
    /// affect lookup before rejection; this is not Linux NO_XDEV containment.
    pub fn open_at(parent: BorrowedFd<'_>, name: &CStr) -> io::Result<Self> {
        crate::Component::new(name.to_bytes())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        crate::ffi::open_directory_at(parent, name).map(Self)
    }

    /// Make exactly ONE getattrlistbulk call into the entire caller buffer.
    /// Returns its exact record count; ONLY zero is native EOF. Errno is captured
    /// immediately, including EINTR, with no retry/refill/allocation/growth.
    /// Bytes beyond those counted records may remain stale. Use decode_census
    /// with this count and a caller entry budget, never infer EOF from bytes.
    /// On error there is no accepted count: potentially modified buffer bytes
    /// are not an observation and must not be decoded using an earlier count.
    ///
    /// After a syscall error the offset is not evidence of progress; it may
    /// also have advanced even if decoding/budget checks later fail. Discard
    /// incomplete censuses, never accept them as empty/clean.
    /// There is no hard bound on uninterruptible kernel I/O time.
    pub fn read_batch(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        crate::ffi::census_batch(self.0.as_fd(), buffer)
    }
}
