use work_darwin::{decode_topology, AccessError};
fn packet() -> Vec<u8> {
    let mut b = vec![0; 60];
    b[4..8].copy_from_slice(&0x8a00_0000u32.to_ne_bytes());
    b[12..16].copy_from_slice(&4u32.to_ne_bytes());
    b[20..24].copy_from_slice(&0xa0u32.to_ne_bytes());
    b[24..32].copy_from_slice(&42u64.to_ne_bytes());
    b[32..36].copy_from_slice(&28i32.to_ne_bytes());
    b[36..40].copy_from_slice(&3u32.to_ne_bytes());
    b[44..48].copy_from_slice(&20i32.to_ne_bytes());
    b[48..52].copy_from_slice(&3u32.to_ne_bytes());
    b[52..56].copy_from_slice(&7i32.to_ne_bytes());
    b[56..60].copy_from_slice(&9i32.to_ne_bytes());
    b.extend_from_slice(b"/a\0\0/b\0\0");
    let len = b.len() as u32;
    b[..4].copy_from_slice(&len.to_ne_bytes());
    b
}
#[test]
fn topology_strict_masks_references_paths_and_mounted_identity() {
    let b = packet();
    let t = decode_topology(&b).unwrap();
    assert_eq!(t.file_id, 42);
    assert_eq!(t.real_fsid, [7, 9]);
    assert!(t.firmlink_alias());
    assert_eq!(t.validate_mount([7, 9]), Ok(()));
    assert_eq!(t.validate_mount([7, 8]), Err(AccessError::Inconsistent));
    for end in 0..b.len() {
        assert!(decode_topology(&b[..end]).is_err());
    }
    for (offset, value) in [
        (4, 0),
        (12, 0),
        (20, 0),
        (32, u32::MAX),
        (36, u32::MAX),
        (40, 4),
        (52, 0),
        (56, 0),
    ] {
        let mut bad = b.clone();
        bad[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
        if offset == 52 || offset == 56 {
            continue;
        } // only the all-zero FSID is unavailable
        assert!(decode_topology(&bad).is_err(), "offset {offset}");
    }
    let mut bad = b.clone();
    bad[52..60].fill(0);
    assert!(decode_topology(&bad).is_err());
}

#[test]
fn topology_rejects_new_route_alias_or_mount_even_when_fsid_matches() {
    let p = packet();
    let mut t = decode_topology(&p).unwrap();
    t.path = b"/alias";
    t.no_firmlink_path = b"/actual";
    let mut child = t;
    child.file_id = 43;
    child.path = b"/alias/child";
    child.no_firmlink_path = b"/actual/child";
    let name = work_darwin::Component::new(b"child").unwrap();
    assert_eq!(t.validate_child(name, child), Ok(()));
    for status in [1, 2, 3] {
        child.mount_status = status;
        assert!(t.validate_child(name, child).is_err());
    }
    child.mount_status = 0;
    child.no_firmlink_path = b"/elsewhere/child";
    assert!(t.validate_child(name, child).is_err());
    child.no_firmlink_path = b"/actual/child";
    child.path = b"/other/child";
    assert!(t.validate_child(name, child).is_err());
    child.path = b"/alias/child";
    child.real_fsid = [7, 8];
    assert!(t.validate_child(name, child).is_err());
}

#[test]
fn topology_rejects_unterminated_relative_and_overlapping_variable_paths() {
    let b = packet();
    for (offset, value) in [(60, b'x'), (62, b'x'), (64, b'x'), (66, b'x')] {
        let mut bad = b.clone();
        bad[offset] = value;
        assert!(decode_topology(&bad).is_err());
    }
    let mut bad = b.clone();
    // Both references claim overlapping objects in one returned record.
    bad[44..48].copy_from_slice(&16i32.to_ne_bytes());
    assert!(decode_topology(&bad).is_err());
}

#[test]
fn mounted_volume_requires_identity_and_terminated_actual_mount_fields() {
    let mut mount = [0u8; 1024];
    mount[..2].copy_from_slice(b"/\0");
    let mut filesystem = [0u8; 16];
    filesystem[..5].copy_from_slice(b"apfs\0");
    let volume = work_darwin::MountedVolume::new([7, 9], 0x0020_0000, mount, filesystem).unwrap();
    assert_eq!(volume.mounted_on(), b"/");
    assert_eq!(volume.filesystem(), b"apfs");
    assert_eq!(
        volume.flags, 0x0020_0000,
        "ignore-ownership evidence cannot be dropped"
    );
    assert!(work_darwin::MountedVolume::new([0, 0], 0, mount, filesystem).is_err());
    assert!(work_darwin::MountedVolume::new([7, 9], 0, [b'/'; 1024], filesystem).is_err());
    assert!(work_darwin::MountedVolume::new([7, 9], 0, mount, [b'a'; 16]).is_err());
    assert!(work_darwin::MountedVolume::new([7, 9], 0, [0; 1024], filesystem).is_err());
}

#[test]
fn topology_names_unavailable_mandatory_masks_separately_from_contradiction() {
    let mut b = packet();
    b[20..24].copy_from_slice(&0x20u32.to_ne_bytes());
    assert_eq!(
        decode_topology(&b),
        Err(AccessError::MissingAttributes {
            common: 0,
            directory: 0,
            extended: 0x80
        })
    );
    b[20..24].copy_from_slice(&0xe0u32.to_ne_bytes());
    assert_eq!(decode_topology(&b), Err(AccessError::Inconsistent));
}
