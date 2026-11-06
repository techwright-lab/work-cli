//! The only unsafe ABI boundary. No raw pointers escape this private module.
//!
//! getattrlistat performs metadata observation, not a readable payload open.
//! Single-component validation and initialized, capped storage are supplied by
//! attributes.rs. This module neither owns FDs nor retries kernel operations.

use std::ffi::CStr;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};

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
