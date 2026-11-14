//! Synthetic wire tests; native schema matching is in native_observations.rs.
use work_darwin::{decode_census, DecodeError};

const RETURNED: u32 = 0x8000_0000;
const NAME: u32 = 1;
const ERROR: u32 = 0x2000_0000;
const FILE_ID: u32 = 0x0200_0000;
const CENSUS: u32 = RETURNED | NAME | ERROR | FILE_ID;

fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_ne_bytes());
}

fn record(name: &[u8]) -> Vec<u8> {
    let length = (44 + name.len() + 1).next_multiple_of(8);
    let mut bytes = vec![0; length];
    put32(&mut bytes, 0, length as u32);
    put32(&mut bytes, 4, CENSUS);
    put32(&mut bytes, 28, 16);
    put32(&mut bytes, 32, (name.len() + 1) as u32);
    bytes[36..44].copy_from_slice(&99_u64.to_ne_bytes());
    bytes[44..44 + name.len()].copy_from_slice(name);
    bytes
}

fn error(bytes: &[u8]) -> DecodeError {
    let mut slots = [None; 2];
    let valid = record(b"valid");
    assert_eq!(decode_census(&valid, 1, &mut slots), Ok(1));
    let result = decode_census(bytes, 1, &mut slots).unwrap_err();
    assert!(slots.iter().all(Option::is_none));
    result
}

#[test]
fn census_proves_names_and_file_ids_without_inventing_generation() {
    let mut bytes = record(b"\xff");
    bytes.extend(record(b"stale"));
    let mut slots = [None; 3];
    assert_eq!(decode_census(&bytes, 2, &mut slots), Ok(2));
    assert_eq!(decode_census(&bytes, 1, &mut slots), Ok(1));
    let entry = slots[0].unwrap();
    assert_eq!(entry.name.as_bytes(), b"\xff");
    assert_eq!(entry.file_id, 99);
    assert_eq!(entry.returned.common, CENSUS);
    assert!(slots[1..].iter().all(Option::is_none));
    assert_eq!(decode_census(&[0xff; 64], 0, &mut slots), Ok(0));
    assert!(slots.iter().all(Option::is_none));
}

#[test]
fn census_budget_and_missing_records_are_not_eof() {
    assert_eq!(
        decode_census(&record(b"a"), 1, &mut []),
        Err(DecodeError::EntryBudget)
    );
    assert_eq!(
        decode_census(&[], usize::MAX, &mut []),
        Err(DecodeError::EntryBudget)
    );
    let mut slots = [None; 2];
    let bytes = record(b"a");
    assert_eq!(
        decode_census(&bytes, 2, &mut slots),
        Err(DecodeError::Truncated)
    );
    assert!(slots.iter().all(Option::is_none));
}

#[test]
fn census_rejects_missing_or_unexpected_masks_and_per_entry_errno() {
    for mask in [RETURNED, RETURNED | NAME | ERROR, NAME | ERROR | FILE_ID] {
        let mut bytes = record(b"a");
        put32(&mut bytes, 4, mask);
        assert_eq!(error(&bytes), DecodeError::MissingAttributes);
    }
    let mut bytes = record(b"a");
    put32(&mut bytes, 4, CENSUS | 0x0008_0000);
    assert_eq!(error(&bytes), DecodeError::UnexpectedAttributes);
    for at in [8, 12, 16, 20] {
        let mut bytes = record(b"a");
        put32(&mut bytes, at, 1);
        assert_eq!(error(&bytes), DecodeError::UnexpectedAttributes);
    }
    let mut bytes = record(b"a");
    put32(&mut bytes, 4, RETURNED | ERROR);
    put32(&mut bytes, 24, 13);
    assert_eq!(error(&bytes), DecodeError::EntryError(13));
    let mut bytes = record(b"a");
    bytes[36..44].fill(0);
    assert_eq!(error(&bytes), DecodeError::UnavailableIdentity);
}

#[test]
fn census_allows_absent_optional_error_field_but_not_absent_identity() {
    let original = record(b"a");
    let mut bytes = original[..24].to_vec();
    bytes.extend_from_slice(&original[28..]);
    bytes.extend_from_slice(&[0; 4]);
    put32(&mut bytes, 4, CENSUS & !ERROR);
    let mut slots = [None; 1];
    assert_eq!(decode_census(&bytes, 1, &mut slots), Ok(1));
    assert_eq!(slots[0].unwrap().name.as_bytes(), b"a");
}

#[test]
fn census_checks_lengths_references_and_single_component_names() {
    let valid = record(b"name");
    for end in 0..valid.len() {
        assert_eq!(error(&valid[..end]), DecodeError::Truncated);
    }
    for length in [0, 8, 16] {
        let mut bytes = valid.clone();
        put32(&mut bytes, 0, length);
        assert_eq!(error(&bytes), DecodeError::InvalidLength);
    }
    for offset in [i32::MIN, -4, 0, 4, i32::MAX - 3] {
        let mut bytes = valid.clone();
        put32(&mut bytes, 28, offset as u32);
        assert_eq!(error(&bytes), DecodeError::InvalidReference);
    }
    let mut bytes = valid.clone();
    put32(&mut bytes, 28, 17);
    assert_eq!(error(&bytes), DecodeError::Misaligned);
    for length in [0, u32::MAX] {
        let mut bytes = valid.clone();
        put32(&mut bytes, 32, length);
        assert_eq!(error(&bytes), DecodeError::InvalidReference);
    }
    for name in [b"".as_slice(), b".", b"..", b"a/b", b"a\0b"] {
        assert_eq!(error(&record(name)), DecodeError::InvalidName);
    }
    let mut bytes = record(b"name");
    bytes[48] = b'x';
    assert_eq!(error(&bytes), DecodeError::InvalidName);
}

#[test]
fn census_second_record_failure_clears_first_and_references_cannot_reach_stale_tail() {
    let first = record(b"first");
    let mut second = record(b"second");
    put32(&mut second, 4, RETURNED | ERROR);
    put32(&mut second, 24, 5);
    let mut bytes = first.clone();
    bytes.extend(second);
    let mut slots = [None; 3];
    assert_eq!(
        decode_census(&bytes, 2, &mut slots),
        Err(DecodeError::EntryError(5))
    );
    assert!(slots.iter().all(Option::is_none));

    let mut bytes = first.clone();
    bytes.extend(record(b"stale"));
    // Reference points into the next record, despite sufficient overall storage.
    put32(&mut bytes, 28, (first.len() + 44 - 28) as u32);
    assert_eq!(error(&bytes), DecodeError::InvalidReference);
}

#[test]
fn census_record_alignment_is_checked_but_slice_base_alignment_is_not_required() {
    let valid = record(b"a");
    let mut bytes = vec![0xff];
    bytes.extend_from_slice(&valid);
    let mut slots = [None; 1];
    assert_eq!(decode_census(&bytes[1..], 1, &mut slots), Ok(1));
    assert_eq!(slots[0].unwrap().name.as_bytes(), b"a");
    for length in [25, 28, 47] {
        let mut bytes = valid.clone();
        put32(&mut bytes, 0, length);
        assert_eq!(error(&bytes), DecodeError::Misaligned);
    }
}
