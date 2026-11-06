//! Directory topology observations under stable observed topology, NOT atomic
//! NO_XDEV containment. Lookup may touch a foreign/aliased filesystem before
//! rejection. Callers must revalidate every ancestor and hold on unknowns.
use crate::access::word;
use crate::AccessError;

pub(crate) fn frame(
    bytes: &[u8],
    fixed: usize,
    common: u32,
    directory: u32,
    extended: u32,
) -> Result<&[u8], AccessError> {
    let length = usize::try_from(word(bytes, 0)?).map_err(|_| AccessError::Malformed)?;
    if length < fixed || length % 4 != 0 {
        return Err(AccessError::Malformed);
    }
    let bytes = bytes.get(..length).ok_or(AccessError::Malformed)?;
    let actual_common = word(bytes, 4)?;
    let actual_directory = word(bytes, 12)?;
    let actual_extended = word(bytes, 20)?;
    if actual_common & !common != 0
        || word(bytes, 8)? != 0
        || actual_directory & !directory != 0
        || word(bytes, 16)? != 0
        || actual_extended & !extended != 0
    {
        return Err(AccessError::Inconsistent);
    }
    if actual_common != common || actual_directory != directory || actual_extended != extended {
        return Err(AccessError::MissingAttributes {
            common: common & !actual_common,
            directory: directory & !actual_directory,
            extended: extended & !actual_extended,
        });
    }
    Ok(bytes)
}

fn reference_range(
    bytes: &[u8],
    at: usize,
    fixed: usize,
) -> Result<std::ops::Range<usize>, AccessError> {
    let relative = i32::from_ne_bytes(word(bytes, at)?.to_ne_bytes());
    let start = at
        .checked_add_signed(relative as isize)
        .ok_or(AccessError::Malformed)?;
    let len = usize::try_from(word(bytes, at + 4)?).map_err(|_| AccessError::Malformed)?;
    let end = start.checked_add(len).ok_or(AccessError::Malformed)?;
    if start < fixed {
        return Err(AccessError::Malformed);
    }
    bytes.get(start..end).ok_or(AccessError::Malformed)?;
    Ok(start..end)
}
pub(crate) fn reference(bytes: &[u8], at: usize, fixed: usize) -> Result<&[u8], AccessError> {
    Ok(&bytes[reference_range(bytes, at, fixed)?])
}
fn path(bytes: &[u8]) -> Result<&[u8], AccessError> {
    if bytes.len() > 1024
        || bytes.first() != Some(&b'/')
        || bytes.last() != Some(&0)
        || bytes[..bytes.len() - 1].contains(&0)
    {
        return Err(AccessError::Malformed);
    }
    Ok(&bytes[..bytes.len() - 1])
}
pub(crate) fn file_id(bytes: &[u8], at: usize) -> Result<u64, AccessError> {
    let id = u64::from_ne_bytes(
        bytes
            .get(at..at + 8)
            .ok_or(AccessError::Malformed)?
            .try_into()
            .map_err(|_| AccessError::Malformed)?,
    );
    if id == 0 {
        return Err(AccessError::Inconsistent);
    }
    Ok(id)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectoryTopology<'a> {
    pub file_id: u64,
    pub real_fsid: [i32; 2],
    pub mount_status: u32,
    pub path: &'a [u8],
    pub no_firmlink_path: &'a [u8],
}
impl DirectoryTopology<'_> {
    /// Reported path inequality, not a universal firmlink detector or an atomic
    /// exclusion guarantee. Inherited aliases are retained in both route paths.
    pub fn firmlink_alias(self) -> bool {
        self.path != self.no_firmlink_path
    }
    /// Cross-check the opened object's actual fstatfs ID, not st_dev or APFS label.
    pub fn validate_mount(self, actual_fsid: [i32; 2]) -> Result<(), AccessError> {
        if self.real_fsid == actual_fsid {
            Ok(())
        } else {
            Err(AccessError::Inconsistent)
        }
    }
    /// Validate a single edge, after opening the directory. This does not replace
    /// fresh full-route revalidation and is not an atomic mount-crossing barrier.
    pub fn validate_child(
        self,
        name: crate::Component<'_>,
        child: Self,
    ) -> Result<(), AccessError> {
        fn suffix<'a>(parent: &[u8], child: &'a [u8]) -> Option<&'a [u8]> {
            let rest = child.strip_prefix(parent)?;
            if parent == b"/" {
                Some(rest)
            } else {
                rest.strip_prefix(b"/")
            }
        }
        // Existing aliases above this edge remain observations, not a blanket
        // Data-volume ban. A newly introduced alias breaks one of these routes.
        if self.real_fsid != child.real_fsid
            || child.mount_status != 0
            || suffix(self.no_firmlink_path, child.no_firmlink_path) != Some(name.as_bytes())
            || suffix(self.path, child.path) != Some(name.as_bytes())
        {
            return Err(AccessError::Inconsistent);
        }
        Ok(())
    }
}

pub(crate) const TOPOLOGY_COMMON: u32 = 0x8a00_0000;
pub(crate) const TOPOLOGY_DIRECTORY: u32 = 4;
pub(crate) const TOPOLOGY_EXTENDED: u32 = 0xa0;

pub fn decode_topology(bytes: &[u8]) -> Result<DirectoryTopology<'_>, AccessError> {
    let bytes = frame(
        bytes,
        60,
        TOPOLOGY_COMMON,
        TOPOLOGY_DIRECTORY,
        TOPOLOGY_EXTENDED,
    )?;
    let mount_status = word(bytes, 40)?;
    if mount_status & !3 != 0 {
        return Err(AccessError::Inconsistent);
    }
    let real_fsid = [word(bytes, 52)? as i32, word(bytes, 56)? as i32];
    if real_fsid == [0, 0] {
        return Err(AccessError::Inconsistent);
    }
    let ordinary = reference_range(bytes, 32, 60)?;
    let physical = reference_range(bytes, 44, 60)?;
    if ordinary.start < physical.end && physical.start < ordinary.end {
        return Err(AccessError::Malformed);
    }
    Ok(DirectoryTopology {
        file_id: file_id(bytes, 24)?,
        real_fsid,
        mount_status,
        path: path(&bytes[ordinary])?,
        no_firmlink_path: path(&bytes[physical])?,
    })
}

pub const TOPOLOGY_BUFFER_SIZE: usize = 60 + 2 * 1024;

/// Actual held-FD fstatfs observation. Neither filesystem label nor equal device
/// numbers are used as mounted identity. Flags (including ignored ownership)
/// remain available to access-policy consumers; this is not APFS qualification.
/// fsid identifies this observed mount, not a durable identity across reboot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountedVolume {
    pub fsid: [i32; 2],
    pub flags: u32,
    mounted_on: [u8; 1024],
    filesystem: [u8; 16],
}
impl MountedVolume {
    pub fn new(
        fsid: [i32; 2],
        flags: u32,
        mounted_on: [u8; 1024],
        filesystem: [u8; 16],
    ) -> Result<Self, AccessError> {
        let mount_end = mounted_on
            .iter()
            .position(|b| *b == 0)
            .ok_or(AccessError::Malformed)?;
        let type_end = filesystem
            .iter()
            .position(|b| *b == 0)
            .ok_or(AccessError::Malformed)?;
        if fsid == [0, 0] || mount_end == 0 || mounted_on[0] != b'/' || type_end == 0 {
            return Err(AccessError::Inconsistent);
        }
        Ok(Self {
            fsid,
            flags,
            mounted_on,
            filesystem,
        })
    }
    pub fn mounted_on(&self) -> &[u8] {
        &self.mounted_on[..self
            .mounted_on
            .iter()
            .position(|b| *b == 0)
            .expect("validated terminator")]
    }
    pub fn filesystem(&self) -> &[u8] {
        &self.filesystem[..self
            .filesystem
            .iter()
            .position(|b| *b == 0)
            .expect("validated terminator")]
    }
}

#[cfg(target_os = "macos")]
pub fn mounted_volume_fd(fd: std::os::fd::BorrowedFd<'_>) -> std::io::Result<MountedVolume> {
    crate::ffi::mounted_volume(fd)
}

/// Read-only held-directory observation plus independent fstatfs consistency
/// check. Uses exactly TOPOLOGY_BUFFER_SIZE caller bytes, initialized once.
#[cfg(target_os = "macos")]
pub fn directory_topology_fd<'a>(
    fd: std::os::fd::BorrowedFd<'_>,
    buffer: &'a mut [u8],
) -> std::io::Result<DirectoryTopology<'a>> {
    let buffer = prepare(buffer)?;
    crate::ffi::topology(fd, None, buffer)?;
    let observed = decode_topology(buffer).map_err(invalid)?;
    observed
        .validate_mount(mounted_volume_fd(fd)?.fsid)
        .map_err(invalid)?;
    Ok(observed)
}
/// Anchored no-follow component evidence. Compare with the actual opened child
/// and its fstatfs observation; this alone is NOT actual-mount/open identity proof.
#[cfg(target_os = "macos")]
pub fn directory_topology_at<'a>(
    parent: std::os::fd::BorrowedFd<'_>,
    name: &std::ffi::CStr,
    buffer: &'a mut [u8],
) -> std::io::Result<DirectoryTopology<'a>> {
    crate::Component::new(name.to_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let buffer = prepare(buffer)?;
    crate::ffi::topology(parent, Some(name), buffer)?;
    decode_topology(buffer).map_err(invalid)
}
#[cfg(target_os = "macos")]
fn prepare(buffer: &mut [u8]) -> std::io::Result<&mut [u8]> {
    let buffer = buffer.get_mut(..TOPOLOGY_BUFFER_SIZE).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "topology buffer budget")
    })?;
    buffer.fill(0);
    Ok(buffer)
}
#[cfg(target_os = "macos")]
fn invalid(error: AccessError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error)
}

/// Directory-only retained FD relative to a held parent, no final symlink follow.
/// Lookup is not NO_XDEV: callers must compare actual topology before accepting.
#[cfg(target_os = "macos")]
pub fn open_directory_at(
    parent: std::os::fd::BorrowedFd<'_>,
    name: &std::ffi::CStr,
) -> std::io::Result<std::os::fd::OwnedFd> {
    crate::Component::new(name.to_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    crate::ffi::open_directory_at(parent, name)
}
