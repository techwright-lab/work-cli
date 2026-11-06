use work_darwin::{decode_filesec, AccessError, GrantExposure, Principal};

fn empty() -> Vec<u8> {
    let mut bytes = vec![0; 44];
    bytes[..4].copy_from_slice(&0x012c_c16du32.to_ne_bytes());
    bytes
}
fn ace(flags: u32, rights: u32) -> Vec<u8> {
    let mut bytes = empty();
    bytes[36..40].copy_from_slice(&1u32.to_ne_bytes());
    bytes.extend_from_slice(&[1; 16]);
    bytes.extend_from_slice(&flags.to_ne_bytes());
    bytes.extend_from_slice(&rights.to_ne_bytes());
    bytes
}
#[test]
fn filesec_requires_complete_exact_bounded_entry_count() {
    let bytes = empty();
    assert_eq!(decode_filesec(&bytes).unwrap().len(), 0);
    for end in 0..44 {
        assert!(decode_filesec(&bytes[..end]).is_err());
    }
    for count in [1, 129, u32::MAX - 1] {
        let mut bytes = empty();
        bytes[36..40].copy_from_slice(&count.to_ne_bytes());
        assert!(decode_filesec(&bytes).is_err());
    }
    let mut bytes = empty();
    bytes.push(0);
    assert_eq!(decode_filesec(&bytes), Err(AccessError::Malformed));
    let bytes = ace(1, 2);
    for end in 44..68 {
        assert!(decode_filesec(&bytes[..end]).is_err());
    }
}
#[test]
fn acl_grants_separate_object_mutation_from_deletion_and_parent_namespace() {
    let entry = |flags, rights| {
        decode_filesec(&ace(flags, rights))
            .unwrap()
            .entries()
            .next()
            .unwrap()
    };
    assert_eq!(
        entry(1, 2 | 8 | 128 | 512 | 2048).exposure(Principal::Unknown, 501),
        Ok(GrantExposure::default())
    );
    let write = entry(1, 4).exposure(Principal::User(502), 501).unwrap();
    assert!(write.object_mutation && write.child_creation);
    assert!(!write.object_deletion && !write.child_deletion);
    let delete = entry(1, 16 | 64)
        .exposure(Principal::User(502), 501)
        .unwrap();
    assert!(!delete.object_mutation && delete.object_deletion && delete.child_deletion);
    // Inherited entries apply. Inherit-only entries do not protect descendants.
    assert!(
        entry(1 | 16, 4)
            .exposure(Principal::User(502), 501)
            .unwrap()
            .object_mutation
    );
    assert_eq!(
        entry(1 | 256, 4).exposure(Principal::Unknown, 501),
        Ok(GrantExposure::default())
    );
    assert_eq!(
        entry(1, 4).exposure(Principal::User(501), 501),
        Ok(GrantExposure::default())
    );
    assert_eq!(
        entry(1, 4).exposure(Principal::Unknown, 501),
        Err(AccessError::UnknownPrincipal)
    );
    assert_eq!(
        entry(1, 4).exposure(Principal::Group(20), 501),
        Err(AccessError::MissingMembership)
    );
    assert_eq!(
        entry(1, 1 << 31).exposure(Principal::User(501), 501),
        Err(AccessError::UnknownRights)
    );
    assert_eq!(
        entry(3, 4).exposure(Principal::User(501), 501),
        Err(AccessError::UnknownFlags)
    );
}

fn access_packet() -> Vec<u8> {
    let mut b = vec![0; 56];
    b[4..8].copy_from_slice(&0x8263_8000u32.to_ne_bytes());
    b[24..28].copy_from_slice(&501u32.to_ne_bytes());
    b[28..32].copy_from_slice(&20u32.to_ne_bytes());
    b[32..36].copy_from_slice(&0o40700u32.to_ne_bytes());
    b[36..40].copy_from_slice(&7u32.to_ne_bytes());
    b[40..44].copy_from_slice(&16i32.to_ne_bytes());
    b[44..48].copy_from_slice(&44u32.to_ne_bytes());
    b[48..56].copy_from_slice(&42u64.to_ne_bytes());
    b.extend_from_slice(&empty());
    b[..4].copy_from_slice(&100u32.to_ne_bytes());
    b
}

#[test]
fn access_packet_preserves_effective_rights_and_refuses_missing_or_inconsistent_evidence() {
    let b = access_packet();
    let observation = work_darwin::decode_access(&b).unwrap();
    assert_eq!(
        (
            observation.owner,
            observation.group,
            observation.mode,
            observation.effective_access,
            observation.file_id
        ),
        (501, 20, 0o40700, 7, 42)
    );
    assert!(observation.acl.is_empty());
    for end in 0..b.len() {
        assert!(work_darwin::decode_access(&b[..end]).is_err());
    }
    for (offset, value) in [(4, 0), (36, 8), (40, u32::MAX), (44, u32::MAX), (48, 0)] {
        let mut bad = b.clone();
        bad[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
        assert!(work_darwin::decode_access(&bad).is_err());
    }
}

#[test]
fn acl_noacl_sentinel_flags_and_maximum_count_are_explicit() {
    let mut absent = empty();
    absent[36..40].copy_from_slice(&u32::MAX.to_ne_bytes());
    let decoded = decode_filesec(&absent).unwrap();
    assert!(decoded.absent && decoded.is_empty());
    assert!(!decode_filesec(&empty()).unwrap().absent);
    let mut unknown = empty();
    unknown[40..44].copy_from_slice(&(1u32 << 31).to_ne_bytes());
    assert_eq!(decode_filesec(&unknown), Err(AccessError::UnknownFlags));
    let mut maximum = empty();
    maximum[36..40].copy_from_slice(&128u32.to_ne_bytes());
    maximum.resize(44 + 128 * 24, 0);
    assert_eq!(decode_filesec(&maximum).unwrap().len(), 128);
    maximum.extend_from_slice(&[0; 24]);
    assert!(decode_filesec(&maximum).is_err());
    let mut malformed = empty();
    malformed[0] = 0;
    assert!(decode_filesec(&malformed).is_err());
}

#[test]
fn sdk27_missing_security_mask_is_unknown_not_acl_absence() {
    // SDK27's owned initial control actually omitted EXTENDED_SECURITY and
    // packed FILEID in its place. Model that framing without treating a missing
    // returned bit as a filesystem promise that there are no ACLs.
    let mut bytes = [0u8; 56];
    bytes[..4].copy_from_slice(&56u32.to_ne_bytes());
    bytes[4..8].copy_from_slice(&0x8223_8000u32.to_ne_bytes());
    bytes[24..28].copy_from_slice(&501u32.to_ne_bytes());
    bytes[28..32].copy_from_slice(&20u32.to_ne_bytes());
    bytes[32..36].copy_from_slice(&0o40700u32.to_ne_bytes());
    bytes[36..40].copy_from_slice(&7u32.to_ne_bytes());
    bytes[40..48].copy_from_slice(&42u64.to_ne_bytes());
    assert_eq!(
        work_darwin::decode_access(&bytes),
        Err(AccessError::MissingAttributes {
            common: 0x0040_0000,
            directory: 0,
            extended: 0
        })
    );
}

#[test]
fn access_rejects_misaligned_acl_wire_offsets() {
    for shift in 1..4 {
        let mut bytes = access_packet();
        bytes.resize(104, 0);
        bytes.copy_within(56..100, 56 + shift);
        bytes[56..56 + shift].fill(0);
        bytes[..4].copy_from_slice(&104u32.to_ne_bytes());
        bytes[40..44].copy_from_slice(&(16 + shift as i32).to_ne_bytes());
        assert_eq!(
            work_darwin::decode_access(&bytes),
            Err(AccessError::Malformed),
            "ACL shift {shift}"
        );
    }
}

#[test]
fn access_aligned_wire_offsets_allow_unaligned_slice_bases() {
    let mut bytes = access_packet();
    bytes.resize(104, 0);
    bytes.copy_within(56..100, 60);
    bytes[56..60].fill(0);
    bytes[..4].copy_from_slice(&104u32.to_ne_bytes());
    bytes[40..44].copy_from_slice(&20i32.to_ne_bytes());
    let expected = work_darwin::decode_access(&bytes).unwrap();
    for prefix in 1..4 {
        let mut storage = vec![0; prefix];
        storage.extend_from_slice(&bytes);
        assert_eq!(work_darwin::decode_access(&storage[prefix..]), Ok(expected));
    }
}
