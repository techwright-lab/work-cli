use work_darwin::{parse_boot_session_uuid, BootSessionError};

const UUID: &[u8; 37] = b"01234567-89AB-CDEF-0123-456789ABCDEF\0";

#[test]
fn boot_uuid_exact_framing_and_case_canonicalization() {
    let parsed = parse_boot_session_uuid(UUID).unwrap();
    assert_eq!(parsed.as_bytes(), b"01234567-89ab-cdef-0123-456789abcdef");
    assert_eq!(
        parse_boot_session_uuid(&UUID.to_ascii_lowercase()).unwrap(),
        parsed
    );
    assert_eq!(format!("{parsed:?}"), "BootSessionUuid([redacted])");
    for end in 0..UUID.len() {
        assert!(parse_boot_session_uuid(&UUID[..end]).is_err());
    }
    let mut extra = UUID.to_vec();
    extra.push(0);
    assert!(matches!(
        parse_boot_session_uuid(&extra),
        Err(BootSessionError::InvalidFrame)
    ));
    let mut extra_text = UUID.to_vec();
    extra_text.extend_from_slice(b"extra");
    assert!(parse_boot_session_uuid(&extra_text).is_err());
}

#[test]
fn boot_uuid_refuses_nil_bad_hex_hyphens_and_embedded_nuls() {
    assert!(matches!(
        parse_boot_session_uuid(b"00000000-0000-0000-0000-000000000000\0"),
        Err(BootSessionError::NilUuid)
    ));
    for at in 0..36 {
        let mut bytes = *UUID;
        bytes[at] = 0;
        assert!(parse_boot_session_uuid(&bytes).is_err());
        bytes[at] = b'g';
        assert!(parse_boot_session_uuid(&bytes).is_err());
    }
    let mut bytes = *UUID;
    bytes[36] = b'x';
    assert!(matches!(
        parse_boot_session_uuid(&bytes),
        Err(BootSessionError::InvalidFrame)
    ));
    assert!(parse_boot_session_uuid(b" 1234567-89ab-cdef-0123-456789abcdef\0").is_err());
}
