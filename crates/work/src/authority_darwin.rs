//! Darwin observation and acquisition beneath the shared authority lifecycle:
//! mounted-volume admission, private-path proof and held-parent lock files.
//! This is validated containment under stable observed topology, not Linux's
//! atomic NO_XDEV: a lookup may touch a foreign volume before the hop refuses.
use rustix::fs::{self as rfs, AtFlags, FileType, Mode, OFlags};
use std::{
    ffi::{CStr, CString},
    fs::{self, File},
    io,
    os::{
        fd::AsFd,
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Component, Path},
};
use work_darwin::{
    directory_topology_at, directory_topology_fd, git_access_at, git_access_fd, mounted_volume_fd,
    open_directory_at, GitAccessDomain, GitAccessObservation, GitAcl, MountedVolume, Principal,
    GIT_ACCESS_BUFFER_SIZE, TOPOLOGY_BUFFER_SIZE,
};

// SDK sys/mount.h.
const MNT_LOCAL: u32 = 0x0000_1000;
const MNT_IGNORE_OWNERSHIP: u32 = 0x0020_0000;
// SDK sys/kauth.h: READ_ATTRIBUTES, READ_SECURITY and SYNCHRONIZE neither
// reveal nor change private state. Every other right granted to an unrelated
// principal breaks the privacy that mode 0700/0600 claims.
const HARMLESS_RIGHTS: u32 = 0x0000_0080 | 0x0000_0800 | 0x0010_0000;
// SDK sys/vnode.h fsobj_type_t.
const VREG: u32 = 1;
const VDIR: u32 = 2;

fn unproven() -> io::Error {
    io::Error::other("Darwin authority evidence unproven")
}

fn component(name: &str) -> io::Result<CString> {
    work_darwin::Component::new(name.as_bytes()).map_err(|_| unproven())?;
    CString::new(name).map_err(|_| unproven())
}

fn identity(meta: &fs::Metadata) -> (u64, u64) {
    (meta.dev(), meta.ino())
}

/// The filesystem label is necessary, never sufficient: callers pair this with
/// the private-path proof and the opened directory's topology observation.
pub(crate) fn qualified_volume(volume: &MountedVolume) -> bool {
    volume.filesystem() == b"apfs"
        && volume.flags & MNT_LOCAL != 0
        && volume.flags & MNT_IGNORE_OWNERSHIP == 0
}

/// One directory hop from a held parent. The name observed through the parent
/// and the directory actually opened must be one object on one mounted volume.
/// A contained hop must also stay on the parent's volume, off any mount point
/// and on the parent's reported route.
fn open_hop(parent: &File, name: &CStr, contained: bool) -> io::Result<File> {
    let mut named_buffer = [0; TOPOLOGY_BUFFER_SIZE];
    let mut opened_buffer = [0; TOPOLOGY_BUFFER_SIZE];
    let named = directory_topology_at(parent.as_fd(), name, &mut named_buffer)?;
    let child = File::from(open_directory_at(parent.as_fd(), name)?);
    // Includes the comparison of the reported real FSID with fstatfs.
    let opened = directory_topology_fd(child.as_fd(), &mut opened_buffer)?;
    if named.file_id != opened.file_id || named.real_fsid != opened.real_fsid {
        return Err(unproven());
    }
    if contained {
        let mut above_buffer = [0; TOPOLOGY_BUFFER_SIZE];
        let above = directory_topology_fd(parent.as_fd(), &mut above_buffer)?;
        let name = work_darwin::Component::new(name.to_bytes()).map_err(|_| unproven())?;
        above.validate_child(name, opened).map_err(|_| unproven())?;
    }
    Ok(child)
}

/// Walks an absolute path from a held root one no-follow component at a time.
/// Ancestors may cross volumes, as the route to user data always does; each
/// crossing is observed, and callers bind the final directory's identity.
pub(crate) fn open_directory(path: &Path) -> io::Result<File> {
    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return Err(unproven());
    }
    let mut held = fs::OpenOptions::new()
        .read(true)
        .custom_flags((OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC).bits() as i32)
        .open("/")?;
    let mut root_buffer = [0; TOPOLOGY_BUFFER_SIZE];
    directory_topology_fd(held.as_fd(), &mut root_buffer)?;
    for component in components {
        let Component::Normal(name) = component else {
            return Err(unproven());
        };
        let name = CString::new(name.as_bytes()).map_err(|_| unproven())?;
        held = open_hop(&held, &name, false)?;
    }
    Ok(held)
}

fn private_acl(
    acl: GitAcl<'_>,
    actor: u32,
    mut resolve: impl FnMut(&[u8; 16]) -> io::Result<Principal>,
) -> bool {
    let GitAcl::Present(acl) = acl else {
        return true;
    };
    // SDK kauth.h: only DEFER_INHERIT and NO_INHERIT are public ACL flags.
    if acl.absent || acl.flags & !0x0003_0000 != 0 {
        return false;
    }
    acl.entries().all(|ace| {
        // Reuses the adapter's rejection of unknown rights, flags and kinds.
        if ace.exposure(Principal::User(actor), actor).is_err() {
            return false;
        }
        match resolve(&ace.principal) {
            Ok(Principal::User(uid)) if uid == actor || uid == 0 => true,
            // Inherit-only grants count: children created here would carry them.
            Ok(Principal::User(_) | Principal::Group(_)) => {
                ace.flags & 15 == 2 || ace.rights & !HARMLESS_RIGHTS == 0
            }
            _ => false,
        }
    })
}

/// Both observations describe the object `meta` describes, on the mounted
/// volume actually holding it. Change time is not compared: cooperating
/// actors legitimately add lock files and append to the database meanwhile.
fn private_evidence(
    observed: &GitAccessObservation<'_>,
    physical: &GitAccessObservation<'_>,
    mount: &MountedVolume,
    meta: &fs::Metadata,
) -> io::Result<()> {
    let actor = rustix::process::geteuid().as_raw();
    let object_type = if meta.is_dir() {
        VDIR
    } else if meta.is_file() {
        VREG
    } else {
        return Err(unproven());
    };
    let owner_access = (meta.mode() >> 6) & 7;
    if observed.fsid == [0, 0]
        || observed.file_id != physical.file_id
        || observed.object_type != physical.object_type
        || observed.owner != physical.owner
        || observed.group != physical.group
        || observed.mode != physical.mode
        || observed.effective_access != physical.effective_access
        || observed.acl != physical.acl
        || physical.fsid != mount.fsid
        || mount.flags & MNT_IGNORE_OWNERSHIP != 0
        || observed.device != meta.dev() as i32
        || observed.file_id != meta.ino()
        || observed.object_type != object_type
        || observed.owner != meta.uid()
        || observed.group != meta.gid()
        || observed.mode & 0o7777 != meta.mode() & 0o7777
        || meta.uid() != actor
        || meta.mode() & 0o077 != 0
        // The kernel must confirm the access the owner bits claim.
        || owner_access & !observed.effective_access != 0
        || !private_acl(observed.acl, actor, work_darwin::principal)
    {
        return Err(unproven());
    }
    Ok(())
}

/// Owner, mode, kernel-reported effective access and ACL of a held object.
pub(crate) fn prove_private(file: &File, meta: &fs::Metadata) -> io::Result<()> {
    let mut buffer = [0; GIT_ACCESS_BUFFER_SIZE];
    let mut physical_buffer = [0; GIT_ACCESS_BUFFER_SIZE];
    let observed = git_access_fd(file.as_fd(), GitAccessDomain::Stat, &mut buffer)?;
    let physical = git_access_fd(
        file.as_fd(),
        GitAccessDomain::Physical,
        &mut physical_buffer,
    )?;
    let mount = mounted_volume_fd(file.as_fd())?;
    private_evidence(&observed, &physical, &mount, meta)
}

fn held_private_directory(path: &Path, named: &fs::Metadata) -> io::Result<File> {
    let held = open_directory(path)?;
    let meta = held.metadata()?;
    if identity(&meta) != identity(named) {
        return Err(unproven());
    }
    prove_private(&held, &meta)?;
    Ok(held)
}

/// Private-path proof for an existing directory the caller has already named.
pub(crate) fn prove_private_directory(path: &Path, named: &fs::Metadata) -> io::Result<()> {
    held_private_directory(path, named).map(drop)
}

/// Admission of a directory that will hold authority state.
pub(crate) fn admit_private_directory(path: &Path, named: &fs::Metadata) -> io::Result<()> {
    let held = held_private_directory(path, named)?;
    if !qualified_volume(&mounted_volume_fd(held.as_fd())?) {
        return Err(unproven());
    }
    Ok(())
}

/// Private-path proof for a named file through its held parent. The file is
/// never opened: its mount evidence is the parent's, which it must share.
pub(crate) fn prove_private_file(path: &Path, named: &fs::Metadata) -> io::Result<()> {
    let parent = open_directory(path.parent().ok_or_else(unproven)?)?;
    let name =
        CString::new(path.file_name().ok_or_else(unproven)?.as_bytes()).map_err(|_| unproven())?;
    let mut buffer = [0; GIT_ACCESS_BUFFER_SIZE];
    let mut physical_buffer = [0; GIT_ACCESS_BUFFER_SIZE];
    let observed = git_access_at(parent.as_fd(), &name, GitAccessDomain::Stat, &mut buffer)?;
    let physical = git_access_at(
        parent.as_fd(),
        &name,
        GitAccessDomain::Physical,
        &mut physical_buffer,
    )?;
    if !named.is_file() || named.dev() != parent.metadata()?.dev() {
        return Err(unproven());
    }
    let mount = mounted_volume_fd(parent.as_fd())?;
    private_evidence(&observed, &physical, &mount, named)
}

/// The authority directory recorded at open, reached by the held-parent walk.
pub(crate) fn open_authority(path: &Path, expected: (u64, u64)) -> io::Result<File> {
    let directory = open_directory(path)?;
    let meta = directory.metadata()?;
    if identity(&meta) != expected {
        return Err(unproven());
    }
    private_lock_directory(&directory)?;
    Ok(directory)
}

fn private_lock_directory(directory: &File) -> io::Result<()> {
    let meta = directory.metadata()?;
    if !meta.is_dir() || meta.mode() & 0o7777 != 0o700 {
        return Err(unproven());
    }
    prove_private(directory, &meta)
}

fn private_lock_file(file: &File) -> io::Result<()> {
    let meta = file.metadata()?;
    if !meta.is_file() || meta.nlink() != 1 || meta.mode() & 0o7777 != 0o600 {
        return Err(unproven());
    }
    prove_private(file, &meta)
}

/// Identity of a name without opening it; stands in for Linux's O_PATH reopen.
fn named_identity(parent: &File, name: &str, kind: FileType) -> io::Result<(u64, u64)> {
    let stat = rfs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)?;
    if FileType::from_raw_mode(stat.st_mode) != kind {
        return Err(unproven());
    }
    Ok((stat.st_dev as u64, stat.st_ino))
}

/// A regular file beneath a held directory. The name is classified before any
/// open, and the opened object must be that file on the directory's volume.
fn open_regular(parent: &File, name: &str, flags: OFlags) -> io::Result<File> {
    component(name)?;
    let named = match named_identity(parent, name, FileType::RegularFile) {
        Ok(id) => Some(id),
        Err(error)
            if flags.contains(OFlags::CREATE)
                && error.raw_os_error() == Some(rustix::io::Errno::NOENT.raw_os_error()) =>
        {
            None
        }
        Err(error) => return Err(error),
    };
    let file = File::from(rfs::openat(
        parent,
        name,
        flags | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::from_raw_mode(0o600),
    )?);
    let meta = file.metadata()?;
    if !meta.is_file()
        || named.is_some_and(|named| named != identity(&meta))
        || meta.dev() != parent.metadata()?.dev()
        || mounted_volume_fd(file.as_fd())?.fsid != mounted_volume_fd(parent.as_fd())?.fsid
    {
        return Err(unproven());
    }
    Ok(file)
}

/// Read-only reopen of a lock directory or lock file beneath a held parent.
pub(crate) fn open_child(parent: &File, name: &str, directory: bool) -> io::Result<File> {
    if directory {
        open_hop(parent, &component(name)?, true)
    } else {
        open_regular(parent, name, OFlags::RDONLY)
    }
}

pub(crate) struct LockRequest<'a> {
    pub(crate) authority: &'a Path,
    pub(crate) authority_id: (u64, u64),
    pub(crate) directory: &'a str,
    pub(crate) name: &'a str,
    /// False acquires only a lock an earlier operation already created.
    pub(crate) create: bool,
    pub(crate) exclusive: bool,
}

pub(crate) struct HeldLock {
    pub(crate) authority: File,
    pub(crate) directory: File,
    pub(crate) file: File,
    pub(crate) authority_id: (u64, u64),
    pub(crate) directory_id: (u64, u64),
    pub(crate) file_id: (u64, u64),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LockRefusal {
    /// Another open file description holds a conflicting lock.
    Busy,
    /// Only without `create`: the lock directory or file does not exist.
    Absent,
    Unproven,
}

fn absent_or_unproven(request: &LockRequest<'_>, error: io::Error) -> LockRefusal {
    if !request.create && error.raw_os_error() == Some(rustix::io::Errno::NOENT.raw_os_error()) {
        LockRefusal::Absent
    } else {
        LockRefusal::Unproven
    }
}

/// The lock sequence shared by checkout and recovery-preparation exclusion.
/// The lock is never waited for and the lock file is never unlinked.
pub(crate) fn acquire_lock(request: &LockRequest<'_>) -> Result<HeldLock, LockRefusal> {
    let unproven = |_: io::Error| LockRefusal::Unproven;
    let authority = open_authority(request.authority, request.authority_id).map_err(unproven)?;
    let authority_id = identity(&authority.metadata().map_err(unproven)?);
    if request.create {
        match rfs::mkdirat(&authority, request.directory, Mode::from_raw_mode(0o700)) {
            Ok(()) => {}
            Err(error) if error == rustix::io::Errno::EXIST => {}
            Err(_) => return Err(LockRefusal::Unproven),
        }
    }
    let directory = open_child(&authority, request.directory, true)
        .map_err(|error| absent_or_unproven(request, error))?;
    private_lock_directory(&directory).map_err(unproven)?;
    let directory_id =
        named_identity(&authority, request.directory, FileType::Directory).map_err(unproven)?;
    if directory_id != identity(&directory.metadata().map_err(unproven)?) {
        return Err(LockRefusal::Unproven);
    }
    let flags = if request.create {
        OFlags::RDWR | OFlags::CREATE
    } else {
        OFlags::RDWR
    };
    let file = open_regular(&directory, request.name, flags)
        .map_err(|error| absent_or_unproven(request, error))?;
    private_lock_file(&file).map_err(unproven)?;
    let file_id =
        named_identity(&directory, request.name, FileType::RegularFile).map_err(unproven)?;
    if file_id != identity(&file.metadata().map_err(unproven)?) {
        return Err(LockRefusal::Unproven);
    }
    let operation = if request.exclusive {
        rfs::FlockOperation::NonBlockingLockExclusive
    } else {
        rfs::FlockOperation::NonBlockingLockShared
    };
    match rfs::flock(&file, operation) {
        Ok(()) => Ok(HeldLock {
            authority,
            directory,
            file,
            authority_id,
            directory_id,
            file_id,
        }),
        Err(error) if error == rustix::io::Errno::WOULDBLOCK => Err(LockRefusal::Busy),
        Err(_) => Err(LockRefusal::Unproven),
    }
}

/// A registered authority laid out as initialization leaves it, built without
/// the store so the native primitives can be driven beneath the closed gates.
#[cfg(test)]
pub(crate) fn registered_authority_fixture() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    std::sync::Arc<crate::store::AuthorityIdentity>,
) {
    use std::os::unix::fs::DirBuilderExt;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let registry = root.join(".work-authorities");
    let authority = root.join("authority");
    let marker = serde_json::json!({"version": 1, "store": authority, "initialized": true});
    for directory in [&registry, &authority] {
        fs::DirBuilder::new().mode(0o700).create(directory).unwrap();
    }
    for (path, bytes) in [
        (registry.join("initialization.lock"), Vec::new()),
        (
            registry.join("initialization.json"),
            marker.to_string().into_bytes(),
        ),
        (registry.join("authorities.sqlite"), Vec::new()),
        (authority.join("store.sqlite"), Vec::new()),
    ] {
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(&bytes).unwrap();
    }
    let identity =
        crate::store::AuthorityIdentity::collect_for_native_test(&registry, &authority).unwrap();
    (temp, registry, identity)
}

// Test-only mutation of a fixture the test created, via the system utility.
#[cfg(test)]
pub(crate) fn grant_acl_fixture(path: &Path, acl: &str) {
    assert!(std::process::Command::new("/bin/chmod")
        .arg("+a")
        .arg(acl)
        .arg(path)
        .env_clear()
        .status()
        .unwrap()
        .success());
}

#[cfg(test)]
mod tests {
    use super::grant_acl_fixture as grant;
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use work_darwin::decode_filesec;

    const LOCKS: &str = "locks-v1";
    const NAME: &str = "operation.lock";

    fn private(path: &Path) {
        fs::DirBuilder::new().mode(0o700).create(path).unwrap();
    }

    fn authority() -> (tempfile::TempDir, std::path::PathBuf, (u64, u64)) {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().canonicalize().unwrap().join("authority");
        private(&path);
        let id = identity(&fs::symlink_metadata(&path).unwrap());
        (temp, path, id)
    }

    fn request(path: &Path, id: (u64, u64), create: bool, exclusive: bool) -> LockRequest<'_> {
        LockRequest {
            authority: path,
            authority_id: id,
            directory: LOCKS,
            name: NAME,
            create,
            exclusive,
        }
    }

    fn refusal(result: Result<HeldLock, LockRefusal>) -> LockRefusal {
        result.err().expect("lock must be refused")
    }

    fn volume(filesystem: &[u8], flags: u32) -> MountedVolume {
        let mut mounted_on = [0; 1024];
        mounted_on[0] = b'/';
        let mut name = [0; 16];
        name[..filesystem.len()].copy_from_slice(filesystem);
        MountedVolume::new([1, 2], flags, mounted_on, name).unwrap()
    }

    #[test]
    fn only_local_apfs_volumes_honouring_ownership_qualify() {
        assert!(qualified_volume(&volume(b"apfs", MNT_LOCAL)));
        assert!(!qualified_volume(&volume(b"hfs", MNT_LOCAL)));
        assert!(!qualified_volume(&volume(b"smbfs", 0)));
        assert!(!qualified_volume(&volume(b"apfs", 0)));
        assert!(!qualified_volume(&volume(
            b"apfs",
            MNT_LOCAL | MNT_IGNORE_OWNERSHIP
        )));
    }

    #[test]
    fn owned_private_directory_is_admitted_and_a_symlinked_route_is_not() {
        let (temp, path, _) = authority();
        let named = fs::symlink_metadata(&path).unwrap();
        admit_private_directory(&path, &named).unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::os::unix::fs::symlink(&path, root.join("alias")).unwrap();
        assert!(admit_private_directory(&root.join("alias"), &named).is_err());
        private(&path.join("inner"));
        let inner = fs::symlink_metadata(path.join("inner")).unwrap();
        assert!(admit_private_directory(&root.join("alias/inner"), &inner).is_err());
    }

    #[test]
    fn acl_granting_others_access_refuses_but_a_harmless_acl_does_not() {
        let (_temp, path, _) = authority();
        grant(&path, "everyone allow readattr,readsecurity");
        let named = fs::symlink_metadata(&path).unwrap();
        admit_private_directory(&path, &named).unwrap();
        grant(&path, "everyone allow list,search");
        let named = fs::symlink_metadata(&path).unwrap();
        assert_eq!(named.mode() & 0o7777, 0o700);
        assert!(admit_private_directory(&path, &named).is_err());
    }

    #[test]
    fn acl_granting_others_access_to_a_file_refuses() {
        let (_temp, path, _) = authority();
        let file = path.join("allocation.lock");
        fs::write(&file, b"").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        prove_private_file(&file, &fs::symlink_metadata(&file).unwrap()).unwrap();
        grant(&file, "everyone allow read");
        let named = fs::symlink_metadata(&file).unwrap();
        assert_eq!(named.mode() & 0o7777, 0o600);
        assert!(prove_private_file(&file, &named).is_err());
    }

    #[test]
    fn denied_owner_access_is_not_proven_by_mode_bits() {
        let (_temp, path, _) = authority();
        grant(&path, "everyone deny search");
        let named = fs::symlink_metadata(&path).unwrap();
        assert_eq!(named.mode() & 0o7777, 0o700);
        assert!(admit_private_directory(&path, &named).is_err());
    }

    fn filesec(rights: u32, flags: u32) -> Vec<u8> {
        let mut bytes = vec![0; 68];
        bytes[..4].copy_from_slice(&0x012c_c16du32.to_ne_bytes());
        bytes[36..40].copy_from_slice(&1u32.to_ne_bytes());
        bytes[44..60].fill(7);
        bytes[60..64].copy_from_slice(&flags.to_ne_bytes());
        bytes[64..68].copy_from_slice(&rights.to_ne_bytes());
        bytes
    }

    fn acl_is_private(rights: u32, flags: u32, principal: Principal) -> bool {
        let bytes = filesec(rights, flags);
        private_acl(
            GitAcl::Present(decode_filesec(&bytes).unwrap()),
            501,
            |_| Ok(principal),
        )
    }

    #[test]
    fn acl_policy_refuses_read_grants_inherited_grants_and_unknown_principals() {
        const ALLOW: u32 = 1;
        const DENY: u32 = 2;
        const ONLY_INHERIT: u32 = 256;
        const READ_DATA: u32 = 2;
        const READ_ATTRIBUTES: u32 = 128;
        for other in [Principal::User(502), Principal::Group(12)] {
            assert!(acl_is_private(READ_ATTRIBUTES, ALLOW, other));
            assert!(acl_is_private(READ_DATA, DENY, other));
            assert!(!acl_is_private(READ_DATA, ALLOW, other));
            assert!(!acl_is_private(READ_DATA, ALLOW | ONLY_INHERIT, other));
        }
        for trusted in [Principal::User(501), Principal::User(0)] {
            assert!(acl_is_private(READ_DATA, ALLOW, trusted));
        }
        assert!(!acl_is_private(READ_ATTRIBUTES, ALLOW, Principal::Unknown));
        assert!(!acl_is_private(1 << 30, ALLOW, Principal::User(501)));
        let absent = {
            let mut bytes = filesec(0, 0);
            bytes.truncate(44);
            bytes[36..40].copy_from_slice(&u32::MAX.to_ne_bytes());
            bytes
        };
        assert!(!private_acl(
            GitAcl::Present(decode_filesec(&absent).unwrap()),
            501,
            |_| unreachable!()
        ));
    }

    #[test]
    fn exclusive_and_shared_locks_contend_across_independent_handles() {
        let (_temp, path, id) = authority();
        let shared = acquire_lock(&request(&path, id, true, false)).unwrap();
        let second = acquire_lock(&request(&path, id, true, false)).unwrap();
        assert_eq!(shared.file_id, second.file_id);
        assert_eq!(
            refusal(acquire_lock(&request(&path, id, true, true))),
            LockRefusal::Busy
        );
        drop(shared);
        assert_eq!(
            refusal(acquire_lock(&request(&path, id, true, true))),
            LockRefusal::Busy
        );
        drop(second);
        let exclusive = acquire_lock(&request(&path, id, true, true)).unwrap();
        assert_eq!(
            refusal(acquire_lock(&request(&path, id, true, false))),
            LockRefusal::Busy
        );
        drop(exclusive);
        acquire_lock(&request(&path, id, true, false)).unwrap();
    }

    #[test]
    fn created_lock_objects_are_private_and_existing_mode_requires_them() {
        let (_temp, path, id) = authority();
        assert_eq!(
            refusal(acquire_lock(&request(&path, id, false, true))),
            LockRefusal::Absent
        );
        assert!(!path.join(LOCKS).exists());
        private(&path.join(LOCKS));
        assert_eq!(
            refusal(acquire_lock(&request(&path, id, false, true))),
            LockRefusal::Absent
        );
        drop(acquire_lock(&request(&path, id, true, true)).unwrap());
        let directory = fs::symlink_metadata(path.join(LOCKS)).unwrap();
        let file = fs::symlink_metadata(path.join(LOCKS).join(NAME)).unwrap();
        assert_eq!(directory.mode() & 0o7777, 0o700);
        assert_eq!(file.mode() & 0o7777, 0o600);
        acquire_lock(&request(&path, id, false, true)).unwrap();
    }

    #[test]
    fn symlinked_lock_directory_and_lock_file_are_refused() {
        let (temp, path, id) = authority();
        let elsewhere = temp.path().canonicalize().unwrap().join("elsewhere");
        private(&elsewhere);
        std::os::unix::fs::symlink(&elsewhere, path.join(LOCKS)).unwrap();
        assert_eq!(
            refusal(acquire_lock(&request(&path, id, true, true))),
            LockRefusal::Unproven
        );
        assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);
        fs::remove_file(path.join(LOCKS)).unwrap();
        private(&path.join(LOCKS));
        let target = elsewhere.join("target.lock");
        fs::write(&target, b"").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&target, path.join(LOCKS).join(NAME)).unwrap();
        assert_eq!(
            refusal(acquire_lock(&request(&path, id, true, true))),
            LockRefusal::Unproven
        );
    }

    #[test]
    fn hard_linked_wrong_mode_and_non_regular_lock_objects_are_refused() {
        let (_temp, path, id) = authority();
        drop(acquire_lock(&request(&path, id, true, true)).unwrap());
        let lock = path.join(LOCKS).join(NAME);
        fs::hard_link(&lock, path.join(LOCKS).join("extra.lock")).unwrap();
        assert_eq!(
            refusal(acquire_lock(&request(&path, id, true, true))),
            LockRefusal::Unproven
        );
        fs::remove_file(path.join(LOCKS).join("extra.lock")).unwrap();
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            refusal(acquire_lock(&request(&path, id, true, true))),
            LockRefusal::Unproven
        );
        fs::remove_file(&lock).unwrap();
        private(&lock);
        assert_eq!(
            refusal(acquire_lock(&request(&path, id, true, true))),
            LockRefusal::Unproven
        );
        fs::remove_dir(&lock).unwrap();
        fs::set_permissions(path.join(LOCKS), fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            refusal(acquire_lock(&request(&path, id, true, true))),
            LockRefusal::Unproven
        );
    }

    #[test]
    fn replaced_authority_directory_is_refused() {
        let (temp, path, id) = authority();
        fs::rename(&path, temp.path().join("retained")).unwrap();
        private(&path);
        assert_eq!(
            refusal(acquire_lock(&request(&path, id, true, true))),
            LockRefusal::Unproven
        );
        assert!(!path.join(LOCKS).exists());
    }

    #[test]
    fn child_reopen_refuses_names_that_are_not_single_components() {
        let (_temp, path, id) = authority();
        let held = acquire_lock(&request(&path, id, true, true)).unwrap();
        open_child(&held.authority, LOCKS, true).unwrap();
        open_child(&held.directory, NAME, false).unwrap();
        for name in ["", ".", "..", "locks-v1/operation.lock", "../authority"] {
            assert!(open_child(&held.authority, name, true).is_err(), "{name}");
            assert!(open_child(&held.authority, name, false).is_err(), "{name}");
        }
        assert!(open_child(&held.authority, LOCKS, false).is_err());
        assert!(open_child(&held.directory, NAME, true).is_err());
    }
}
