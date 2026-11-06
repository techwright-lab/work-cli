//! Bounded read-only access evidence, not an authority to mutate or read payload.
//! ACL wire layout follows SDK27 sys/kauth.h; integers are native endian.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessError {
    Malformed,
    EntryBudget,
    UnknownRights,
    UnknownFlags,
    UnknownPrincipal,
    MissingMembership,
    Inconsistent,
    /// Requested bits absent from returned masks; never inferred from defaults.
    MissingAttributes {
        common: u32,
        directory: u32,
        extended: u32,
    },
}

impl std::fmt::Display for AccessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Darwin access evidence: {self:?}")
    }
}
impl std::error::Error for AccessError {}

pub(crate) fn word(bytes: &[u8], offset: usize) -> Result<u32, AccessError> {
    let end = offset.checked_add(4).ok_or(AccessError::Malformed)?;
    Ok(u32::from_ne_bytes(
        bytes
            .get(offset..end)
            .ok_or(AccessError::Malformed)?
            .try_into()
            .map_err(|_| AccessError::Malformed)?,
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Acl<'a> {
    entries: &'a [u8],
    pub flags: u32,
    /// NOACL is distinct from an empty ACL; neither is mode-only access proof.
    pub absent: bool,
}

impl<'a> Acl<'a> {
    pub fn len(self) -> usize {
        self.entries.len() / 24
    }
    pub fn is_empty(self) -> bool {
        self.entries.is_empty()
    }
    pub fn entries(self) -> impl Iterator<Item = Ace> + 'a {
        self.entries.as_chunks::<24>().0.iter().map(|entry| Ace {
            principal: entry[..16].try_into().expect("fixed entry"),
            flags: u32::from_ne_bytes(entry[16..20].try_into().expect("fixed entry")),
            rights: u32::from_ne_bytes(entry[20..24].try_into().expect("fixed entry")),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ace {
    pub principal: [u8; 16],
    pub flags: u32,
    pub rights: u32,
}

/// Decode exactly one kauth_filesec, capped at SDK ACL_MAX_ENTRIES (128).
/// No owner/group UUID inference: getattrlist documents only its ACL as used.
pub fn decode_filesec(bytes: &[u8]) -> Result<Acl<'_>, AccessError> {
    if word(bytes, 0)? != 0x012c_c16d {
        return Err(AccessError::Malformed);
    }
    let count = word(bytes, 36)?;
    let flags = word(bytes, 40)?;
    if flags & !0x0003_ffff != 0 {
        return Err(AccessError::UnknownFlags);
    }
    let absent = count == u32::MAX;
    let count = if absent {
        0
    } else {
        usize::try_from(count).map_err(|_| AccessError::EntryBudget)?
    };
    if count > 128 {
        return Err(AccessError::EntryBudget);
    }
    let end = count
        .checked_mul(24)
        .and_then(|n| n.checked_add(44))
        .ok_or(AccessError::Malformed)?;
    if bytes.len() != end {
        return Err(AccessError::Malformed);
    }
    Ok(Acl {
        entries: &bytes[44..],
        flags,
        absent,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Principal {
    User(u32),
    Group(u32),
    Unknown,
}

/// Potential unrelated-principal grants. False is not complete protection proof:
/// ownership, modes, mount ownership semantics, ancestors and fresh effective
/// access must also be checked. Denies are never used to cancel other grants.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GrantExposure {
    pub object_mutation: bool,
    pub object_deletion: bool,
    pub child_creation: bool,
    pub child_deletion: bool,
}
impl Ace {
    pub fn exposure(
        self,
        principal: Principal,
        trusted_uid: u32,
    ) -> Result<GrantExposure, AccessError> {
        // Generic rights are retained as evidence but not interpreted as harmless.
        if self.rights & !0x0010_3ffe != 0 {
            return Err(AccessError::UnknownRights);
        }
        if self.flags & !0x1ff != 0 || !matches!(self.flags & 15, 1 | 2) {
            return Err(AccessError::UnknownFlags);
        }
        let exposure = GrantExposure {
            object_mutation: self.rights & (4 | 32 | 256 | 1024 | 4096 | 8192) != 0,
            object_deletion: self.rights & 16 != 0,
            child_creation: self.rights & (4 | 32) != 0,
            child_deletion: self.rights & 64 != 0,
        };
        if self.flags & 15 == 2 || self.flags & 256 != 0 || exposure == GrantExposure::default() {
            return Ok(GrantExposure::default());
        }
        match principal {
            Principal::User(uid) if uid == trusted_uid => Ok(GrantExposure::default()),
            Principal::User(_) => Ok(exposure),
            // Current-user membership cannot establish absence of OTHER members.
            Principal::Group(_) => Err(AccessError::MissingMembership),
            Principal::Unknown => Err(AccessError::UnknownPrincipal),
        }
    }
}

/// A single returned-mask-validated snapshot. USERACCESS is kernel-reported
/// effective-UID R_OK/W_OK/X_OK; it says nothing about unrelated users or delete.
/// No snapshot proves absence of concurrent changes, writer FDs or mmap writers.
/// file_id is volume-local, not mandatory payload-generation evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessObservation<'a> {
    pub owner: u32,
    pub group: u32,
    pub mode: u32,
    pub effective_access: u32,
    pub file_id: u64,
    pub acl: Acl<'a>,
}
pub(crate) const ACCESS_COMMON: u32 = 0x8263_8000;
pub const ACCESS_BUFFER_SIZE: usize = 56 + 44 + 128 * 24;

pub fn decode_access(bytes: &[u8]) -> Result<AccessObservation<'_>, AccessError> {
    let bytes = crate::topology::frame(bytes, 56, ACCESS_COMMON, 0, 0)?;
    let effective_access = word(bytes, 36)?;
    if effective_access & !7 != 0 {
        return Err(AccessError::Inconsistent);
    }
    Ok(AccessObservation {
        owner: word(bytes, 24)?,
        group: word(bytes, 28)?,
        mode: word(bytes, 32)?,
        effective_access,
        file_id: crate::topology::file_id(bytes, 48)?,
        acl: decode_filesec(crate::topology::reference(bytes, 40, 56)?)?,
    })
}

/// Borrows an already-held object FD. One bounded read-only syscall; no retry,
/// allocation, mode-only fallback, readable payload open or permission repair.
/// Reobserve routes/identities around use; this call does not protect ancestors.
/// Darwin may omit EXTENDED_SECURITY (observed on a newly owned SDK27 control).
/// Missing returned ACL evidence refuses; it is NOT interpreted as ACL absence.
#[cfg(target_os = "macos")]
pub fn access_fd<'a>(
    fd: std::os::fd::BorrowedFd<'_>,
    buffer: &'a mut [u8],
) -> std::io::Result<AccessObservation<'a>> {
    let buffer = buffer.get_mut(..ACCESS_BUFFER_SIZE).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "access buffer budget")
    })?;
    buffer.fill(0);
    crate::ffi::access_fd(fd, buffer)?;
    decode_access(buffer)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

/// Resolve one ACL UUID, without treating current-user group membership as proof
/// that the group excludes unrelated principals. Unknown IDs are explicit.
/// One call, no retry; this is not a wall-clock bound on the membership service.
#[cfg(target_os = "macos")]
pub fn principal(uuid: &[u8; 16]) -> std::io::Result<Principal> {
    crate::ffi::principal(uuid)
}

/// One no-follow component metadata observation, without opening payload or
/// inferring that the containing route is protected. Retains native errno.
#[cfg(target_os = "macos")]
pub fn access_at<'a>(
    parent: std::os::fd::BorrowedFd<'_>,
    name: &std::ffi::CStr,
    buffer: &'a mut [u8],
) -> std::io::Result<AccessObservation<'a>> {
    crate::Component::new(name.to_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let buffer = buffer.get_mut(..ACCESS_BUFFER_SIZE).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "access buffer budget")
    })?;
    buffer.fill(0);
    crate::ffi::access_at(parent, name, buffer)?;
    decode_access(buffer).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}
