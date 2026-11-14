#![cfg(target_os = "macos")]
//! Native observer controls using retained fixtures and read-only route metadata.

#[test]
fn native_git_access_root_correlates_default_device_and_actual_mount() {
    use std::{
        fs::File,
        os::{fd::AsFd, unix::fs::MetadataExt},
    };
    use work_darwin::{
        git_access_fd, mounted_volume_fd, GitAccessDomain, GitAcl, GIT_ACCESS_BUFFER_SIZE,
    };
    let root = File::open("/").unwrap();
    let meta = root.metadata().unwrap();
    let mount = mounted_volume_fd(root.as_fd()).unwrap();
    let mut buffer = [0; GIT_ACCESS_BUFFER_SIZE];
    let observed = git_access_fd(root.as_fd(), GitAccessDomain::Stat, &mut buffer).unwrap();
    let mut physical_buffer = [0; GIT_ACCESS_BUFFER_SIZE];
    let physical = git_access_fd(
        root.as_fd(),
        GitAccessDomain::Physical,
        &mut physical_buffer,
    )
    .unwrap();
    eprintln!("root: observed={observed:?} mount_fsid={:?} flags={:x} stat dev={} ino={} uid={} gid={} mode={:o} ctime=({}, {})", mount.fsid, mount.flags, meta.dev(), meta.ino(), meta.uid(), meta.gid(), meta.mode(), meta.ctime(), meta.ctime_nsec());
    if let GitAcl::Present(acl) = observed.acl {
        for ace in acl.entries() {
            eprintln!(
                "root ACE={ace:?} resolved={:?}",
                work_darwin::principal(&ace.principal)
            );
        }
    }
    assert_eq!(observed.device, meta.dev() as i32);
    assert_eq!(observed.file_id, meta.ino());
    assert_eq!(physical.fsid, mount.fsid);
    assert_eq!(physical.file_id, observed.file_id);
    assert_eq!(physical.object_type, observed.object_type);
    assert_eq!(physical.owner, observed.owner);
    assert_eq!(physical.group, observed.group);
    assert_eq!(physical.mode, observed.mode);
    assert_eq!(physical.effective_access, observed.effective_access);
    assert_eq!(physical.change_time, observed.change_time);
    assert_eq!(physical.acl, observed.acl);
    assert_eq!(observed.change_time, (meta.ctime(), meta.ctime_nsec()));
    if let Some(git) = std::env::var_os("WORK_TEST_NATIVE_GIT") {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let path = std::path::PathBuf::from(git);
        for directory in path
            .ancestors()
            .skip(1)
            .filter(|p| *p != std::path::Path::new("/"))
        {
            let parent = File::open(directory.parent().unwrap()).unwrap();
            let held = File::open(directory).unwrap();
            let meta = held.metadata().unwrap();
            let mount = mounted_volume_fd(held.as_fd()).unwrap();
            let name = CString::new(directory.file_name().unwrap().as_bytes()).unwrap();
            let observed = work_darwin::git_access_at(
                parent.as_fd(),
                &name,
                GitAccessDomain::Stat,
                &mut buffer,
            )
            .unwrap();
            let physical = work_darwin::git_access_at(
                parent.as_fd(),
                &name,
                GitAccessDomain::Physical,
                &mut physical_buffer,
            )
            .unwrap();
            eprintln!("route {}: attrdev={} statdev={} attrfsid={:?} mountfsid={:?} owner={} mode={:o} access={} acl={:?}", directory.display(), observed.device, meta.dev(), observed.fsid, mount.fsid, observed.owner, observed.mode, observed.effective_access, observed.acl);
            if let GitAcl::Present(acl) = observed.acl {
                for ace in acl.entries() {
                    eprintln!("principal {:?}", work_darwin::principal(&ace.principal));
                }
            }
            assert_eq!(
                observed.device,
                meta.dev() as i32,
                "{}",
                directory.display()
            );
            assert_eq!(observed.file_id, meta.ino(), "{}", directory.display());
            assert_eq!(physical.fsid, mount.fsid, "{}", directory.display());
            assert_eq!(
                physical.file_id,
                observed.file_id,
                "{}",
                directory.display()
            );
            assert_eq!(physical.object_type, observed.object_type);
            assert_eq!(physical.owner, observed.owner);
            assert_eq!(physical.group, observed.group);
            assert_eq!(physical.mode, observed.mode);
            assert_eq!(physical.effective_access, observed.effective_access);
            assert_eq!(physical.change_time, observed.change_time);
            assert_eq!(physical.acl, observed.acl);
        }
    }
}
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::Write;
use std::os::fd::AsFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use work_darwin::{
    git_access_at, git_access_fd, mounted_volume_fd, GitAccessDomain, GitAcl,
    GIT_ACCESS_BUFFER_SIZE,
};

#[test]
fn native_git_access_supported_null_acl_matches_owned_file_and_held_directory_metadata() {
    let root = std::env::temp_dir().join(format!("work-darwin-git-access-{}", std::process::id()));
    DirBuilder::new().mode(0o700).create(&root).unwrap();
    let path = root.join("entry");
    {
        // Creating our own fixture is the only regular-file open in this test.
        // The production observer must obtain metadata without a payload FD.
        let mut created = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&path)
            .unwrap();
        created
            .write_all(b"owned native Git access control\n")
            .unwrap();
    }
    let held = File::open(&root).unwrap();
    let volume = mounted_volume_fd(held.as_fd()).unwrap();
    let mut file_buffer = [0xff; GIT_ACCESS_BUFFER_SIZE];
    let mut directory_buffer = [0xff; GIT_ACCESS_BUFFER_SIZE];

    let file_before = fs::symlink_metadata(&path).unwrap();
    let file = git_access_at(
        held.as_fd(),
        c"entry",
        GitAccessDomain::Stat,
        &mut file_buffer,
    )
    .unwrap();
    let file_after = fs::symlink_metadata(&path).unwrap();
    let directory_before = held.metadata().unwrap();
    // Exercise a held directory directly; no "."/".." validation bypass and no
    // need to open a regular executable to cover the route-root observer seam.
    let directory =
        git_access_fd(held.as_fd(), GitAccessDomain::Stat, &mut directory_buffer).unwrap();
    let directory_after = held.metadata().unwrap();

    for (observation, before, after, object_type) in [
        (file, file_before, file_after, 1),                // VREG
        (directory, directory_before, directory_after, 2), // VDIR
    ] {
        let identity = |metadata: &fs::Metadata| {
            (
                metadata.dev(),
                metadata.ino(),
                metadata.mode(),
                metadata.uid(),
                metadata.gid(),
                metadata.ctime(),
                metadata.ctime_nsec(),
            )
        };
        assert_eq!(identity(&before), identity(&after));
        assert_eq!(observation.device, before.dev() as i32);
        assert_eq!(observation.file_id, before.ino());
        assert_eq!(observation.object_type, object_type);
        assert_eq!(before.is_file(), object_type == 1);
        assert_eq!(before.is_dir(), object_type == 2);
        assert_eq!(observation.owner, before.uid());
        assert_eq!(observation.group, before.gid());
        // getattrlist(2) guarantees ACCESSMASK permissions, not its type bits.
        assert_eq!(observation.mode & 0o7777, before.mode() & 0o7777);
        assert_eq!(before.mode() & 0o7777, 0o700);
        assert_eq!(observation.effective_access, 7); // R_OK | W_OK | X_OK
        assert_eq!(
            observation.change_time,
            (before.ctime(), before.ctime_nsec())
        );
        // Compare FSID to an actual held-directory mount observation, never to
        // st_dev. Both objects are freshly created in this one private root.
        assert_eq!(observation.fsid, volume.fsid);
        assert_eq!(observation.acl, GitAcl::SupportedNone);
    }
    // Retain the root and payload for the owning qualification fixture.
}
