#![cfg(target_os = "macos")]
//! Read-only existing-directory topology and newly owned replacement fixtures.
use std::fs::{self, DirBuilder, File};
use std::os::fd::AsFd;
use std::os::unix::fs::DirBuilderExt;
use work_darwin::{
    directory_topology_at, directory_topology_fd, mounted_volume_fd, open_directory_at, Component,
    TOPOLOGY_BUFFER_SIZE,
};
#[test]
fn native_topology_opened_and_anchored_identity_agree_and_replacements_are_visible() {
    let root = std::env::temp_dir().join(format!("work-darwin-topology-{}", std::process::id()));
    DirBuilder::new().mode(0o700).create(&root).unwrap();
    fs::create_dir(root.join("parent")).unwrap();
    fs::create_dir(root.join("parent/child")).unwrap();
    let outer = File::open(&root).unwrap();
    let parent = open_directory_at(outer.as_fd(), c"parent").unwrap();
    let child = open_directory_at(parent.as_fd(), c"child").unwrap();
    let mut a = [0; TOPOLOGY_BUFFER_SIZE];
    let mut b = [0; TOPOLOGY_BUFFER_SIZE];
    let mut c = [0; TOPOLOGY_BUFFER_SIZE];
    let p = directory_topology_fd(parent.as_fd(), &mut a).unwrap();
    let opened = directory_topology_fd(child.as_fd(), &mut b).unwrap();
    let anchored = directory_topology_at(parent.as_fd(), c"child", &mut c).unwrap();
    assert_eq!(opened, anchored);
    p.validate_child(Component::new(b"child").unwrap(), opened)
        .unwrap();
    let original_id = opened.file_id;
    fs::rename(root.join("parent"), root.join("retained-parent")).unwrap();
    fs::create_dir(root.join("parent")).unwrap();
    fs::create_dir(root.join("parent/child")).unwrap();
    let replacement = open_directory_at(outer.as_fd(), c"parent").unwrap();
    let now = directory_topology_at(replacement.as_fd(), c"child", &mut c).unwrap();
    assert_ne!(now.file_id, original_id);
    let old = directory_topology_fd(child.as_fd(), &mut b).unwrap();
    assert_eq!(old.file_id, original_id);
    assert!(
        p.validate_child(Component::new(b"child").unwrap(), old)
            .is_err(),
        "stale ancestor path must fail"
    );
    assert!(open_directory_at(outer.as_fd(), c"../escape").is_err());
    let mut short = [0xff; TOPOLOGY_BUFFER_SIZE - 1];
    assert_eq!(
        directory_topology_fd(child.as_fd(), &mut short)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidInput
    );
    assert!(short.iter().all(|b| *b == 0xff));
    assert_eq!(
        directory_topology_at(outer.as_fd(), c"missing", &mut a)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ENOENT)
    );
    std::os::unix::fs::symlink("parent", root.join("link")).unwrap();
    assert!(open_directory_at(outer.as_fd(), c"link").is_err());
}
#[test]
fn native_topology_existing_directories_report_real_mounts_without_foreign_volume_claims() {
    for path in ["/", "/System/Volumes/Data", "/Users", "/private/tmp"] {
        let held = File::open(path).unwrap();
        let mut b = [0xff; TOPOLOGY_BUFFER_SIZE];
        let observed = directory_topology_fd(held.as_fd(), &mut b).unwrap();
        let volume = mounted_volume_fd(held.as_fd()).unwrap();
        assert_eq!(observed.real_fsid, volume.fsid);
        assert_eq!(volume.mounted_on().first(), Some(&b'/'));
        assert!(!volume.filesystem().is_empty());
        assert_ne!(observed.real_fsid, [0, 0]);
        assert_eq!(observed.no_firmlink_path.first(), Some(&b'/'));
        eprintln!(
            "readonly existing directory {path}: mount_status={} firmlink_alias={}",
            observed.mount_status,
            observed.firmlink_alias()
        );
    }
    // No mount creation, device opening, foreign-volume or reboot qualification.
}
