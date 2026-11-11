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

/// ACL evidence from a successful legacy-schema observation. SupportedNone is
/// a bounded zero-length reference, not a missing returned bit or NOACL sentinel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GitAcl<'a> {
    SupportedNone,
    Present(Acl<'a>),
}

/// The native query's device/FSID domain. REALDEV changes both fields; it must
/// not be compared directly to normal stat's logical device on volume groups.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GitAccessDomain {
    Stat,
    Physical,
}

/// Correlating metadata and ACL from one legacy-schema observation. This is not
/// an atomic permissions snapshot; callers must bracket it with route/metadata
/// checks. Device and filesystem IDs are separate identity domains. Object type
/// is the SDK fsobj_type_t value, to be checked by the consuming access policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GitAccessObservation<'a> {
    /// Domain selected by the query; Stat matches normal stat, Physical does not.
    pub device: i32,
    /// Stat FSID may be logical on volume groups. Only the Physical observation
    /// is correlated to an independently held mounted_volume_fd. Neither field
    /// implies equivalence of device and FSID identity domains.
    pub fsid: [i32; 2],
    pub object_type: u32,
    pub change_time: (i64, i64),
    pub owner: u32,
    pub group: u32,
    pub mode: u32,
    pub effective_access: u32,
    pub file_id: u64,
    pub acl: GitAcl<'a>,
}

#[cfg(target_os = "macos")]
pub(crate) const GIT_ACCESS_COMMON: u32 = 0x0263_880e;
pub const GIT_ACCESS_BUFFER_SIZE: usize = 68 + 44 + 128 * 24;

/// Decode the 64-bit legacy Git access schema (common mask 0x0263880e).
/// The caller must obtain it without RETURNED_ATTRS or PACK_INVAL_ATTRS: only a
/// successful supported-attribute query gives a null reference its meaning.
/// SDK getattrlist(2) aligns all fields to four bytes, including the timespec
/// at offset 20 and FILEID at offset 60. No native structure casts are used.
pub fn decode_git_access(bytes: &[u8]) -> Result<GitAccessObservation<'_>, AccessError> {
    let length = usize::try_from(word(bytes, 0)?).map_err(|_| AccessError::Malformed)?;
    if length < 68 || length % 4 != 0 {
        return Err(AccessError::Malformed);
    }
    if length > GIT_ACCESS_BUFFER_SIZE {
        return Err(AccessError::EntryBudget);
    }
    let bytes = bytes.get(..length).ok_or(AccessError::Malformed)?;
    let effective_access = word(bytes, 48)?;
    let change_time = (
        i64::from_ne_bytes(
            bytes[20..28]
                .try_into()
                .map_err(|_| AccessError::Malformed)?,
        ),
        i64::from_ne_bytes(
            bytes[28..36]
                .try_into()
                .map_err(|_| AccessError::Malformed)?,
        ),
    );
    if effective_access & !7 != 0 || !(0..1_000_000_000).contains(&change_time.1) {
        return Err(AccessError::Inconsistent);
    }
    let security = crate::topology::reference(bytes, 52, 68)?;
    let acl = if security.is_empty() {
        GitAcl::SupportedNone
    } else {
        let acl = decode_filesec(security)?;
        if acl.absent {
            return Err(AccessError::Inconsistent);
        }
        GitAcl::Present(acl)
    };
    Ok(GitAccessObservation {
        device: word(bytes, 4)? as i32,
        fsid: [word(bytes, 8)? as i32, word(bytes, 12)? as i32],
        object_type: word(bytes, 16)?,
        change_time,
        owner: word(bytes, 36)?,
        group: word(bytes, 40)?,
        mode: word(bytes, 44)?,
        effective_access,
        file_id: crate::topology::file_id(bytes, 60)?,
        acl,
    })
}

#[cfg(target_os = "macos")]
fn prepare_git_access(buffer: &mut [u8]) -> std::io::Result<&mut [u8]> {
    let buffer = buffer.get_mut(..GIT_ACCESS_BUFFER_SIZE).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "Git access buffer budget")
    })?;
    buffer.fill(0);
    Ok(buffer)
}

/// One legacy no-follow component observation using an initialized fixed caller
/// buffer. No payload open, refetch, retry or mode-only fallback. Native errors
/// retain errno; invalid or unavailable evidence refuses. The default device
/// and FSID domains require independent metadata/mounted-volume correlation.
#[cfg(target_os = "macos")]
pub fn git_access_at<'a>(
    parent: std::os::fd::BorrowedFd<'_>,
    name: &std::ffi::CStr,
    domain: GitAccessDomain,
    buffer: &'a mut [u8],
) -> std::io::Result<GitAccessObservation<'a>> {
    crate::Component::new(name.to_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let buffer = prepare_git_access(buffer)?;
    crate::ffi::git_access_at(parent, name, domain, buffer)?;
    decode_git_access(buffer).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Observe an already-held directory, including a route root, without a fake
/// "."/".." component or regular-file open. The caller supplies a directory FD.
/// One bounded legacy syscall with the same correlation requirements as
/// git_access_at; no retry, refetch or fallback on unsupported evidence.
#[cfg(target_os = "macos")]
pub fn git_access_fd<'a>(
    directory: std::os::fd::BorrowedFd<'_>,
    domain: GitAccessDomain,
    buffer: &'a mut [u8],
) -> std::io::Result<GitAccessObservation<'a>> {
    let buffer = prepare_git_access(buffer)?;
    crate::ffi::git_access_fd(directory, domain, buffer)?;
    decode_git_access(buffer).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
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
