//! The only unsafe ABI boundary. No raw pointers escape this private module.
//!
//! getattrlistat performs metadata observation, not a readable payload open.
//! Single-component validation and initialized, capped storage are supplied by
//! attributes.rs. No kernel operation is retried. Fresh directory opens transfer
//! ownership exactly once into OwnedFd; bulk reads only borrow that owned FD.

use std::ffi::CStr;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

// Tie the portable wire schema to the pinned Darwin libc definitions.
const _: () = {
    assert!(crate::decode::RETURNED == libc::ATTR_CMN_RETURNED_ATTRS);
    assert!(crate::decode::NAME == libc::ATTR_CMN_NAME);
    assert!(crate::decode::GENERATION == libc::ATTR_CMN_GEN_COUNT);
    assert!(crate::decode::FILE_ID == libc::ATTR_CMN_FILEID);
};

pub(crate) fn attributes_at(
    parent: BorrowedFd<'_>,
    name: &CStr,
    buffer: &mut [u8],
) -> io::Result<()> {
    let mut requested = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: libc::ATTR_CMN_RETURNED_ATTRS
            | libc::ATTR_CMN_GEN_COUNT
            | libc::ATTR_CMN_FILEID,
        volattr: 0,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    };
    // SAFETY: parent remains borrowed and open throughout the call. name is a
    // live NUL-terminated CStr. requested is a fully initialized ABI attrlist.
    // buffer is exclusively borrowed, initialized and writable for buffer.len()
    // bytes. The kernel copies results within that bound; we decode only after
    // success with separate checked byte reads, never typed pointer dereferences.
    let result = unsafe {
        libc::getattrlistat(
            parent.as_raw_fd(),
            name.as_ptr(),
            (&mut requested as *mut libc::attrlist).cast(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            (libc::FSOPT_NOFOLLOW | libc::FSOPT_ATTR_CMN_EXTENDED).into(),
        )
    };
    if result == -1 {
        // Capture errno immediately; never retry an interrupted/failed observation.
        return Err(io::Error::last_os_error());
    }
    if result != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected getattrlistat result",
        ));
    }
    Ok(())
}

pub(crate) fn open_directory_at(parent: BorrowedFd<'_>, name: &CStr) -> io::Result<OwnedFd> {
    // SAFETY: parent is borrowed live for the call, and name is a live CStr,
    // prevalidated as one component. O_CREAT is absent, so no mode argument is
    // needed. The fresh FD is transferred once to OwnedFd, never aliased as owned.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat succeeded and returned a new owned descriptor. No other
    // owner exists, and OwnedFd will close it exactly once.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

pub(crate) fn census_batch(fd: BorrowedFd<'_>, buffer: &mut [u8]) -> io::Result<usize> {
    let mut requested = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: crate::decode::CENSUS,
        volattr: 0,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    };
    // SAFETY: fd remains live; requested is fully initialized and uses only the
    // fixed census schema. buffer is exclusively borrowed initialized writable
    // storage of exactly buffer.len() bytes (zero length is permitted to fail).
    // No typed reads occur; the safe decoder uses the exact returned count.
    // Bulk enumeration reports the entries themselves, including symlinks;
    // no invalid-attribute packing, generation or follow fallback is requested.
    let result = unsafe {
        libc::getattrlistbulk(
            fd.as_raw_fd(),
            (&mut requested as *mut libc::attrlist).cast(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            0,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    usize::try_from(result).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected getattrlistbulk result",
        )
    })
}

pub(crate) fn boot_session_uuid(buffer: &mut [u8; 37]) -> io::Result<usize> {
    let mut length = buffer.len();
    // SAFETY: the constant name is NUL-terminated and live. buffer and length
    // are initialized, exclusively borrowed writable storage. A null newp and
    // zero newlen make this strictly read-only. The returned length is checked
    // by safe framing code; ENOMEM/EINTR are errors, never probe/refill retries.
    let result = unsafe {
        libc::sysctlbyname(
            c"kern.bootsessionuuid".as_ptr(),
            buffer.as_mut_ptr().cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    if result != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected sysctl result",
        ));
    }
    Ok(length)
}
