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

// SDK27 sys/attr.h: these schemas deliberately request neither generation nor
// NAME census fields. Mandatory payload generation remains a separate API.
const _: () = {
    assert!(
        crate::access::ACCESS_COMMON
            == libc::ATTR_CMN_RETURNED_ATTRS
                | libc::ATTR_CMN_OWNERID
                | libc::ATTR_CMN_GRPID
                | libc::ATTR_CMN_ACCESSMASK
                | libc::ATTR_CMN_USERACCESS
                | libc::ATTR_CMN_EXTENDED_SECURITY
                | libc::ATTR_CMN_FILEID
    );
    assert!(
        crate::access::GIT_ACCESS_COMMON
            == libc::ATTR_CMN_DEVID
                | libc::ATTR_CMN_FSID
                | libc::ATTR_CMN_OBJTYPE
                | libc::ATTR_CMN_CHGTIME
                | libc::ATTR_CMN_OWNERID
                | libc::ATTR_CMN_GRPID
                | libc::ATTR_CMN_ACCESSMASK
                | libc::ATTR_CMN_USERACCESS
                | libc::ATTR_CMN_EXTENDED_SECURITY
                | libc::ATTR_CMN_FILEID
    );
    assert!(
        crate::topology::TOPOLOGY_COMMON
            == libc::ATTR_CMN_RETURNED_ATTRS | libc::ATTR_CMN_FILEID | libc::ATTR_CMN_FULLPATH
    );
    assert!(crate::topology::TOPOLOGY_DIRECTORY == libc::ATTR_DIR_MOUNTSTATUS);
    assert!(
        crate::topology::TOPOLOGY_EXTENDED
            == libc::ATTR_CMNEXT_NOFIRMLINKPATH | libc::ATTR_CMNEXT_REALFSID
    );
    assert!(std::mem::size_of::<libc::fsid_t>() == std::mem::size_of::<[i32; 2]>());
};

fn observe_list(
    fd: BorrowedFd<'_>,
    name: Option<&CStr>,
    requested: libc::attrlist,
    buffer: &mut [u8],
) -> io::Result<()> {
    observe_list_with_options(fd, name, requested, buffer, libc::FSOPT_ATTR_CMN_EXTENDED)
}

fn observe_list_with_options(
    fd: BorrowedFd<'_>,
    name: Option<&CStr>,
    mut requested: libc::attrlist,
    buffer: &mut [u8],
    options: u32,
) -> io::Result<()> {
    // SAFETY: fd is borrowed live, optional name is a live CStr validated as one
    // component by the safe caller. requested is initialized. Caller buffer is
    // initialized, exclusively borrowed and writable for exactly its len bytes.
    // No typed result dereferences, retries, allocation or raw pointer escape.
    let result = unsafe {
        match name {
            Some(name) => libc::getattrlistat(
                fd.as_raw_fd(),
                name.as_ptr(),
                (&mut requested as *mut libc::attrlist).cast(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                (libc::FSOPT_NOFOLLOW | options).into(),
            ),
            None => libc::fgetattrlist(
                fd.as_raw_fd(),
                (&mut requested as *mut libc::attrlist).cast(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                options,
            ),
        }
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    if result != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected attribute observation result",
        ));
    }
    Ok(())
}
fn list(commonattr: u32, dirattr: u32, forkattr: u32) -> libc::attrlist {
    libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr,
        volattr: 0,
        dirattr,
        fileattr: 0,
        forkattr,
    }
}
// Legacy schema: omitting RETURNED_ATTRS/PACK_INVAL preserves the kernel's
// requested-attribute support gate. REPORT_FULLSIZE makes truncation visible.
// SDK getattrlist(2): RETURN_REALDEV changes both DEVID and FSID. Keep the
// selection explicit; consumers correlate Stat to metadata and Physical to the
// actual held mount, checking all other object/ACL evidence across both calls.
fn git_access_options(domain: crate::GitAccessDomain) -> u32 {
    libc::FSOPT_REPORT_FULLSIZE
        | match domain {
            crate::GitAccessDomain::Stat => 0,
            crate::GitAccessDomain::Physical => libc::FSOPT_RETURN_REALDEV,
        }
}
pub(crate) fn git_access_fd(
    fd: BorrowedFd<'_>,
    domain: crate::GitAccessDomain,
    buffer: &mut [u8],
) -> io::Result<()> {
    observe_list_with_options(
        fd,
        None,
        list(crate::access::GIT_ACCESS_COMMON, 0, 0),
        buffer,
        git_access_options(domain),
    )
}
pub(crate) fn git_access_at(
    fd: BorrowedFd<'_>,
    name: &CStr,
    domain: crate::GitAccessDomain,
    buffer: &mut [u8],
) -> io::Result<()> {
    observe_list_with_options(
        fd,
        Some(name),
        list(crate::access::GIT_ACCESS_COMMON, 0, 0),
        buffer,
        git_access_options(domain),
    )
}
pub(crate) fn access_fd(fd: BorrowedFd<'_>, buffer: &mut [u8]) -> io::Result<()> {
    observe_list(fd, None, list(crate::access::ACCESS_COMMON, 0, 0), buffer)
}
pub(crate) fn access_at(fd: BorrowedFd<'_>, name: &CStr, buffer: &mut [u8]) -> io::Result<()> {
    observe_list(
        fd,
        Some(name),
        list(crate::access::ACCESS_COMMON, 0, 0),
        buffer,
    )
}
pub(crate) fn topology(
    fd: BorrowedFd<'_>,
    name: Option<&CStr>,
    buffer: &mut [u8],
) -> io::Result<()> {
    observe_list(
        fd,
        name,
        list(
            crate::topology::TOPOLOGY_COMMON,
            crate::topology::TOPOLOGY_DIRECTORY,
            crate::topology::TOPOLOGY_EXTENDED,
        ),
        buffer,
    )
}

unsafe extern "C" {
    // SDK27 membership.h. Unlike ordinary syscalls this returns errno directly.
    fn mbr_uuid_to_id(uuid: *const u8, id: *mut libc::id_t, kind: *mut libc::c_int) -> libc::c_int;
}
pub(crate) fn principal(uuid: &[u8; 16]) -> io::Result<crate::Principal> {
    if *uuid == [0; 16] {
        return Ok(crate::Principal::Unknown);
    }
    let mut id: libc::id_t = 0;
    let mut kind: libc::c_int = -1;
    // SAFETY: uuid is exactly the SDK's 16-byte uuid_t input. Both output
    // pointers designate initialized, exclusively borrowed correctly typed locals.
    // No result is consumed after a nonzero return; no retries/retained pointers.
    let result = unsafe { mbr_uuid_to_id(uuid.as_ptr(), &mut id, &mut kind) };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result));
    }
    Ok(match kind {
        0 => crate::Principal::User(id),
        1 => crate::Principal::Group(id),
        _ => crate::Principal::Unknown,
    })
}

pub(crate) fn mounted_volume(fd: BorrowedFd<'_>) -> io::Result<crate::MountedVolume> {
    // SAFETY: statfs is a C POD of integer scalars and fixed arrays, for which
    // zero is valid. Initialization also prevents stale bytes on partial writes.
    let mut value: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: live borrowed fd and exclusive writable correctly sized statfs.
    let result = unsafe { libc::fstatfs(fd.as_raw_fd(), &mut value) };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    if result != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected fstatfs result",
        ));
    }
    // SAFETY: SDK sys/mount.h defines fsid_t as two int32 values. libc keeps the
    // field private; sizes are asserted above. All bit patterns are valid i32s.
    let fsid = unsafe { std::mem::transmute::<libc::fsid_t, [i32; 2]>(value.f_fsid) };
    crate::MountedVolume::new(
        fsid,
        value.f_flags,
        value.f_mntonname.map(|b| b as u8),
        value.f_fstypename.map(|b| b as u8),
    )
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}
