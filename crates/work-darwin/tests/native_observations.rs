#![cfg(target_os = "macos")]
//! Development ABI checks only, on newly created fixture entries. No lifecycle qualification.
use std::ffi::{CString, OsString};
use std::fs::{self, File};
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{symlink, MetadataExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use work_darwin::{boot_session_uuid, decode_census, DecodeError, DirectoryCursor};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn fixture() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "work-darwin-native-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&path).unwrap();
    path
}

#[test]
fn native_counted_censuses_match_owned_entries_and_nofollow_identities() {
    let root = fixture();
    let mut names = vec![b"file".as_slice(), b"dir", b"link"];
    fs::write(root.join("file"), b"owned payload").unwrap();
    fs::create_dir(root.join("dir")).unwrap();
    match fs::write(root.join(OsString::from_vec(b"\xff".to_vec())), b"owned") {
        Ok(()) => names.push(b"\xff"),
        Err(error) => {
            assert_eq!(error.raw_os_error(), Some(libc::EILSEQ));
            eprintln!("native non-UTF8 fixture construction refused with EILSEQ; arbitrary-byte native enumeration NOT exercised");
        }
    }
    symlink("file", root.join("link")).unwrap();
    let parent = File::open(&root).unwrap();
    let mut baseline = Vec::new();
    for _ in 0..3 {
        // Each census gets a fresh open, not a dup sharing a directory offset.
        let mut cursor = DirectoryCursor::open_at(parent.as_fd(), c"dir").unwrap();
        let mut empty_storage = [0xff; 4096];
        assert_eq!(cursor.read_batch(&mut empty_storage).unwrap(), 0);
        // Open the fixture itself relative to its held parent using a single component.
        let outer = File::open(root.parent().unwrap()).unwrap();
        let name = CString::new(root.file_name().unwrap().as_encoded_bytes()).unwrap();
        let mut cursor = DirectoryCursor::open_at(outer.as_fd(), &name).unwrap();
        let mut buffer = [0xff; 64]; // One entry per call; caller performs bounded refills.
        let mut observed = Vec::new();
        for request in 0..8 {
            let count = cursor.read_batch(&mut buffer).unwrap();
            assert!(count <= 1, "no hidden refill or growth beyond caller bytes");
            let mut slots = [None; 16];
            assert_eq!(decode_census(&buffer, count, &mut slots), Ok(count));
            if count == 0 {
                assert!(slots.iter().all(Option::is_none));
                break;
            }
            assert!(
                request < 7,
                "census must reach explicit native EOF within caller budget"
            );
            for entry in slots[..count].iter().flatten() {
                // The native request and actual returned masks must match this schema.
                // ERROR is requested but Darwin 27 omits it on successful entries.
                // Both legal forms are strictly decoded, not PACK_INVAL_ATTRS.
                assert!(matches!(entry.returned.common, 0x8200_0001 | 0xa200_0001));
                assert_eq!(
                    (
                        entry.returned.volume,
                        entry.returned.directory,
                        entry.returned.file,
                        entry.returned.fork
                    ),
                    (0, 0, 0, 0)
                );
                let name = entry.name.as_bytes();
                assert!(names.contains(&name));
                let metadata =
                    fs::symlink_metadata(root.join(OsString::from_vec(name.to_vec()))).unwrap();
                assert_eq!(entry.file_id, metadata.ino());
                observed.push((name.to_vec(), entry.file_id));
            }
        }
        observed.sort();
        let mut expected_names = names.clone();
        expected_names.sort();
        assert_eq!(
            observed
                .iter()
                .map(|(name, _)| name.as_slice())
                .collect::<Vec<_>>(),
            expected_names
        );
        if baseline.is_empty() {
            baseline = observed;
        } else {
            assert_eq!(observed, baseline);
        }
    }
    // Retain disposable fixture/evidence; no test cleanup or real paths.
}

#[test]
fn native_fresh_opens_have_independent_offsets_and_small_buffers_do_not_grow() {
    let root = fixture();
    fs::create_dir(root.join("dir")).unwrap();
    for name in ["first", "second", "third"] {
        fs::write(root.join("dir").join(name), b"owned").unwrap();
    }
    let parent = File::open(&root).unwrap();
    let mut first = DirectoryCursor::open_at(parent.as_fd(), c"dir").unwrap();
    let mut second = DirectoryCursor::open_at(parent.as_fd(), c"dir").unwrap();
    let mut a = [0xff; 64];
    let mut b = [0xff; 64];
    assert_eq!(first.read_batch(&mut a).unwrap(), 1);
    assert_eq!(second.read_batch(&mut b).unwrap(), 1);
    let mut a_slots = [None; 1];
    let mut b_slots = [None; 1];
    decode_census(&a, 1, &mut a_slots).unwrap();
    decode_census(&b, 1, &mut b_slots).unwrap();
    assert_eq!(
        a_slots, b_slots,
        "fresh cursors must not share a dup offset"
    );
    assert_eq!(first.read_batch(&mut a).unwrap(), 1);
    assert_eq!(first.read_batch(&mut a).unwrap(), 1);
    assert_eq!(first.read_batch(&mut a).unwrap(), 0);
    // Advancing first does not advance second.
    assert_eq!(second.read_batch(&mut b).unwrap(), 1);
    assert_eq!(second.read_batch(&mut b).unwrap(), 1);
    assert_eq!(second.read_batch(&mut b).unwrap(), 0);

    fs::create_dir(root.join("long")).unwrap();
    fs::write(root.join("long").join("x".repeat(200)), b"owned").unwrap();
    let mut cursor = DirectoryCursor::open_at(parent.as_fd(), c"long").unwrap();
    assert_eq!(
        cursor.read_batch(&mut [0; 64]).unwrap_err().raw_os_error(),
        Some(libc::ERANGE)
    );
}

#[test]
fn native_errno_budget_and_stale_tail_are_explicit() {
    let root = fixture();
    fs::write(root.join("file"), b"owned").unwrap();
    let parent = File::open(&root).unwrap();
    assert_eq!(
        DirectoryCursor::open_at(parent.as_fd(), c"missing")
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ENOENT)
    );
    assert_eq!(
        DirectoryCursor::open_at(parent.as_fd(), c"file")
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ENOTDIR)
    );
    symlink("file", root.join("link")).unwrap();
    assert!(DirectoryCursor::open_at(parent.as_fd(), c"link").is_err());
    assert!(DirectoryCursor::open_at(parent.as_fd(), c"../escape").is_err());
    fs::create_dir(root.join("dir")).unwrap();
    symlink("dir", root.join("dirlink")).unwrap();
    assert!(DirectoryCursor::open_at(parent.as_fd(), c"dirlink").is_err());
    fs::write(root.join("dir/a"), b"owned").unwrap();
    let mut cursor = DirectoryCursor::open_at(parent.as_fd(), c"dir").unwrap();
    assert_eq!(
        cursor.read_batch(&mut []).unwrap_err().raw_os_error(),
        Some(libc::ERANGE)
    );
    let mut buffer = [0xff; 4096];
    let count = cursor.read_batch(&mut buffer).unwrap();
    assert_eq!(count, 1);
    assert_eq!(
        decode_census(&buffer, count, &mut []),
        Err(DecodeError::EntryBudget)
    );
    let stale = buffer;
    assert_eq!(cursor.read_batch(&mut buffer).unwrap(), 0);
    let mut slots = [None; 2];
    // Even an intact previous batch must be ignored at actual count=0.
    assert_eq!(decode_census(&stale, 0, &mut slots), Ok(0));
    assert!(slots.iter().all(Option::is_none));
}

#[test]
fn native_boot_session_repeats_without_publishing_host_uuid() {
    let first = boot_session_uuid().unwrap();
    for _ in 0..4 {
        assert!(
            boot_session_uuid().unwrap() == first,
            "boot session changed; no fallback or lifecycle inference"
        );
    }
}
