use work_darwin::{decode_git_access, AccessError, GitAcl};

#[test]
fn legacy_supported_null_acl_requires_valid_reference_and_preserves_correlation_metadata() {
    // Independent 64-bit legacy getattrlist ABI fixture, not decoder constants.
    // SDK26.5 sys/attr.h and getattrlist(2): common mask 0x0263880e requests
    // DEVID, FSID, OBJTYPE, CHGTIME, OWNERID, GRPID, ACCESSMASK, USERACCESS,
    // EXTENDED_SECURITY and FILEID, in that order, with four-byte alignment.
    // No RETURNED_ATTRS or PACK_INVAL_ATTRS: unsupported evidence must fail the
    // native getter, not become an omitted field or an inferred empty ACL.
    let mut bytes = [0u8; 68];
    bytes[0..4].copy_from_slice(&68u32.to_ne_bytes());
    bytes[4..8].copy_from_slice(&0x0100_0004i32.to_ne_bytes());
    bytes[8..12].copy_from_slice(&0x1234_5678i32.to_ne_bytes());
    bytes[12..16].copy_from_slice(&(-7i32).to_ne_bytes());
    bytes[16..20].copy_from_slice(&1u32.to_ne_bytes()); // VREG
    bytes[20..28].copy_from_slice(&1_700_000_000i64.to_ne_bytes());
    bytes[28..36].copy_from_slice(&123_456_789i64.to_ne_bytes());
    bytes[36..40].copy_from_slice(&501u32.to_ne_bytes());
    bytes[40..44].copy_from_slice(&20u32.to_ne_bytes());
    bytes[44..48].copy_from_slice(&0o100755u32.to_ne_bytes());
    // R_OK | X_OK
    bytes[48..52].copy_from_slice(&5u32.to_ne_bytes());
    // XNU26 ac9718fb1af618d5ce8678d0dc6e8a58f252216f,
    // bsd/vfs/vfs_attrlist.c:184-227,2084-2097 packs supported NULL ACL as
    // a zero-length reference with a computed offset, not an all-zero pair.
    // The reference at 52 points +16 to the variable region at frame end 68.
    bytes[52..56].copy_from_slice(&16i32.to_ne_bytes());
    bytes[56..60].copy_from_slice(&0u32.to_ne_bytes());
    bytes[60..68].copy_from_slice(&42u64.to_ne_bytes());

    let observation = decode_git_access(&bytes).unwrap();
    assert_eq!(
        (
            observation.device,
            observation.fsid,
            observation.object_type,
            observation.change_time,
            observation.file_id,
        ),
        (
            0x0100_0004,
            [0x1234_5678, -7],
            1,
            (1_700_000_000, 123_456_789),
            42,
        )
    );
    assert_eq!(
        (
            observation.owner,
            observation.group,
            observation.mode,
            observation.effective_access,
        ),
        (501, 20, 0o100755, 5)
    );
    assert_eq!(observation.acl, GitAcl::SupportedNone);

    // Zero length alone is not supported-null evidence: this points inside
    // the fixed fields rather than at the bounded variable region.
    bytes[52..60].fill(0);
    assert_eq!(decode_git_access(&bytes), Err(AccessError::Malformed));
}
