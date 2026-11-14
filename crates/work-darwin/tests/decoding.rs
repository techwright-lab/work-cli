use work_darwin::{decode_attributes, decode_bulk, Component, DecodeError};

const RETURNED: u32 = 0x8000_0000;
const NAME: u32 = 1;
const ERROR: u32 = 0x2000_0000;
const GENERATION: u32 = 0x0008_0000;
const FILE_ID: u32 = 0x0200_0000;
const IDENTITY: u32 = RETURNED | GENERATION | FILE_ID;
const BULK: u32 = IDENTITY | NAME | ERROR;

fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_ne_bytes());
}

fn attributes() -> Vec<u8> {
    let mut bytes = vec![0; 36];
    put32(&mut bytes, 0, 36);
    put32(&mut bytes, 4, IDENTITY);
    put32(&mut bytes, 24, 7);
    bytes[28..36].copy_from_slice(&99_u64.to_ne_bytes());
    bytes
}

fn bulk(name: &[u8]) -> Vec<u8> {
    let len = (48 + name.len() + 1).next_multiple_of(8);
    let mut bytes = vec![0; len];
    put32(&mut bytes, 0, len as u32);
    put32(&mut bytes, 4, BULK);
    put32(&mut bytes, 28, 20); // relative to the name reference, not the group
    put32(&mut bytes, 32, (name.len() + 1) as u32);
    put32(&mut bytes, 36, 7);
    bytes[40..48].copy_from_slice(&99_u64.to_ne_bytes());
    bytes[48..48 + name.len()].copy_from_slice(name);
    bytes
}

fn bulk_error(bytes: &[u8]) -> DecodeError {
    let mut output = [None; 1];
    let error = decode_bulk(bytes, 1, &mut output).unwrap_err();
    assert!(output.iter().all(Option::is_none));
    error
}

#[test]
fn exact_returned_count_ignores_stale_tail_and_clears_unused_slots() {
    let mut bytes = bulk(b"first");
    bytes.extend(bulk(b"stale"));
    let mut output = [None; 3];
    assert_eq!(decode_bulk(&bytes, 2, &mut output), Ok(2));
    assert_eq!(decode_bulk(&bytes, 1, &mut output), Ok(1));
    let first = output[0].unwrap();
    assert_eq!(first.name.as_bytes(), b"first");
    assert_eq!(first.attributes.file_id, 99);
    assert_eq!(first.attributes.generation, 7);
    assert_eq!(first.attributes.returned.common, BULK);
    assert!(output[1..].iter().all(Option::is_none));
    assert_eq!(decode_bulk(&bytes, 0, &mut output), Ok(0));
    assert!(output.iter().all(Option::is_none));
    assert_eq!(decode_bulk(&[0xff; 64], 0, &mut output), Ok(0));
}

#[test]
fn count_is_bounded_by_caller_storage_not_a_hidden_allocation() {
    assert_eq!(
        decode_bulk(&bulk(b"a"), 1, &mut []),
        Err(DecodeError::EntryBudget)
    );
    assert_eq!(
        decode_bulk(&[], usize::MAX, &mut []),
        Err(DecodeError::EntryBudget)
    );
}

#[test]
fn exact_count_does_not_turn_a_missing_record_into_eof() {
    let mut output = [None; 2];
    let bytes = bulk(b"a");
    assert_eq!(
        decode_bulk(&bytes, 2, &mut output),
        Err(DecodeError::Truncated)
    );
    assert!(output.iter().all(Option::is_none));
}

#[test]
fn every_truncated_record_prefix_is_rejected() {
    let bytes = bulk(b"name");
    for end in 0..bytes.len() {
        assert_eq!(
            bulk_error(&bytes[..end]),
            DecodeError::Truncated,
            "end={end}"
        );
    }
}

#[test]
fn group_lengths_must_progress_and_be_aligned() {
    for len in [0, 1, 4, 8, 16] {
        let mut bytes = bulk(b"a");
        put32(&mut bytes, 0, len);
        assert_eq!(bulk_error(&bytes), DecodeError::InvalidLength, "len={len}");
    }
    let mut bytes = bulk(b"a");
    put32(&mut bytes, 0, 55);
    assert_eq!(bulk_error(&bytes), DecodeError::Misaligned);
    put32(&mut bytes, 0, u32::MAX - 7);
    assert_eq!(bulk_error(&bytes), DecodeError::Truncated);
}

#[test]
fn second_record_is_validated_before_any_results_are_accepted() {
    let mut bytes = bulk(b"a");
    let at = bytes.len();
    bytes.extend(bulk(b"b"));
    put32(&mut bytes, at, 0);
    let mut output = [None; 2];
    assert_eq!(
        decode_bulk(&bytes, 2, &mut output),
        Err(DecodeError::InvalidLength)
    );
    assert!(output.iter().all(Option::is_none));
}

#[test]
fn missing_mandatory_masks_are_not_default_values() {
    for missing in [RETURNED, NAME, GENERATION, FILE_ID] {
        let mut bytes = bulk(b"a");
        put32(&mut bytes, 4, BULK & !missing);
        assert_eq!(bulk_error(&bytes), DecodeError::MissingAttributes);
    }
}

#[test]
fn unexpected_common_or_other_group_masks_are_rejected() {
    let mut bytes = bulk(b"a");
    put32(&mut bytes, 4, BULK | 2);
    assert_eq!(bulk_error(&bytes), DecodeError::UnexpectedAttributes);
    for at in [8, 12, 16, 20] {
        let mut bytes = bulk(b"a");
        put32(&mut bytes, at, 1);
        assert_eq!(bulk_error(&bytes), DecodeError::UnexpectedAttributes);
    }
}

#[test]
fn entry_errno_is_reported_even_when_identity_is_missing() {
    let mut bytes = vec![0; 32];
    put32(&mut bytes, 0, 32);
    put32(&mut bytes, 4, RETURNED | ERROR);
    put32(&mut bytes, 24, 13);
    assert_eq!(bulk_error(&bytes), DecodeError::EntryError(13));
}

#[test]
fn absent_optional_error_field_changes_field_offsets() {
    let mut bytes = bulk(b"a");
    bytes.drain(24..28);
    bytes.extend([0; 4]);
    let len = bytes.len();
    put32(&mut bytes, 0, len as u32);
    put32(&mut bytes, 4, BULK & !ERROR);
    let mut output = [None; 1];
    assert_eq!(decode_bulk(&bytes, 1, &mut output), Ok(1));
    assert_eq!(output[0].unwrap().name.as_bytes(), b"a");
}

#[test]
fn signed_name_references_cannot_underflow_overlap_or_escape_the_record() {
    for offset in [i32::MIN, -32, -28, -4, 0, 4, 16, i32::MAX - 3] {
        let mut bytes = bulk(b"a");
        put32(&mut bytes, 28, offset as u32);
        assert_eq!(
            bulk_error(&bytes),
            DecodeError::InvalidReference,
            "offset={offset}"
        );
    }
    let mut bytes = bulk(b"a");
    put32(&mut bytes, 28, 21);
    assert_eq!(bulk_error(&bytes), DecodeError::Misaligned);
}

#[test]
fn name_lengths_cannot_be_zero_overflow_or_reach_a_stale_next_record() {
    for len in [0, u32::MAX, 9] {
        let mut bytes = bulk(b"a");
        put32(&mut bytes, 32, len);
        bytes.extend(bulk(b"stale"));
        assert_eq!(
            bulk_error(&bytes),
            DecodeError::InvalidReference,
            "len={len}"
        );
    }
}

#[test]
fn names_require_a_single_final_nul_and_a_valid_component() {
    let mut bytes = bulk(b"a");
    bytes[49] = b'x';
    assert_eq!(bulk_error(&bytes), DecodeError::InvalidName);
    for name in [b"".as_slice(), b".", b"..", b"a/b", b"a\0b"] {
        assert_eq!(
            bulk_error(&bulk(name)),
            DecodeError::InvalidName,
            "name={name:?}"
        );
        assert_eq!(Component::new(name), Err(DecodeError::InvalidName));
    }
}

#[test]
fn names_are_borrowed_bytes_not_lossy_text_or_copies() {
    let bytes = bulk(&[0xff, 0xfe]);
    let mut output = [None; 1];
    assert_eq!(decode_bulk(&bytes, 1, &mut output), Ok(1));
    let name = output[0].unwrap().name.as_bytes();
    assert_eq!(name, &[0xff, 0xfe]);
    assert_eq!(name.as_ptr(), bytes[48..].as_ptr());
    assert!(Component::new(&[0xff]).is_ok());
}

#[test]
fn single_attributes_decode_four_byte_aligned_u64_and_ignore_storage_tail() {
    let mut bytes = attributes();
    bytes.extend([0xff; 64]);
    let observed = decode_attributes(&bytes).unwrap();
    assert_eq!(observed.file_id, 99);
    assert_eq!(observed.generation, 7);
    assert_eq!(observed.returned.common, IDENTITY);
}

#[test]
fn single_attributes_reject_every_truncated_prefix() {
    let bytes = attributes();
    for end in 0..bytes.len() {
        assert_eq!(
            decode_attributes(&bytes[..end]),
            Err(DecodeError::Truncated),
            "end={end}"
        );
    }
}

#[test]
fn single_attributes_reject_incomplete_or_unexpected_masks() {
    for missing in [RETURNED, GENERATION, FILE_ID] {
        let mut bytes = attributes();
        put32(&mut bytes, 4, IDENTITY & !missing);
        assert_eq!(
            decode_attributes(&bytes),
            Err(DecodeError::MissingAttributes)
        );
    }
    let mut bytes = attributes();
    put32(&mut bytes, 4, IDENTITY | NAME);
    assert_eq!(
        decode_attributes(&bytes),
        Err(DecodeError::UnexpectedAttributes)
    );
}

#[test]
fn single_attribute_lengths_must_match_the_fixed_schema() {
    for len in [0, 4, 20] {
        let mut bytes = attributes();
        put32(&mut bytes, 0, len);
        assert_eq!(decode_attributes(&bytes), Err(DecodeError::InvalidLength));
    }
    let mut bytes = attributes();
    put32(&mut bytes, 0, 35);
    assert_eq!(decode_attributes(&bytes), Err(DecodeError::Misaligned));
    put32(&mut bytes, 0, u32::MAX - 3);
    assert_eq!(decode_attributes(&bytes), Err(DecodeError::Truncated));
    let mut bytes = attributes();
    bytes.extend([0; 4]);
    put32(&mut bytes, 0, 40);
    assert_eq!(decode_attributes(&bytes), Err(DecodeError::InvalidLength));
}

#[test]
fn zero_generation_or_file_id_is_unavailable_not_valid_evidence() {
    for at in [24, 28] {
        let mut bytes = attributes();
        put32(&mut bytes, at, 0);
        assert_eq!(
            decode_attributes(&bytes),
            Err(DecodeError::UnavailableIdentity)
        );
    }
    for at in [36, 40] {
        let mut bytes = bulk(b"a");
        put32(&mut bytes, at, 0);
        assert_eq!(bulk_error(&bytes), DecodeError::UnavailableIdentity);
    }
}

#[test]
fn byte_slice_base_alignment_is_not_required_for_safe_decoding() {
    let mut bytes = vec![0];
    bytes.extend(bulk(b"a"));
    let mut output = [None; 1];
    assert_eq!(decode_bulk(&bytes[1..], 1, &mut output), Ok(1));
}
