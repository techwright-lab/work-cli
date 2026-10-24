//! Test source authored before the corresponding A2/A3 logic. CI-only; no RED/GREEN claim.

#[test]
fn sha1_index_and_blob_known_vectors() {
    for (input, expected) in [
        (b"".as_slice(), "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        (b"abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
        ),
    ] {
        for chunk in [1, 7, 64] {
            let mut hash = Sha1::new();
            for part in input.chunks(chunk) {
                hash.update(part);
            }
            assert_eq!(hex(&hash.finish()), expected);
        }
    }
    // Independently published padding-boundary vectors for repeated ASCII 'a'.
    for (length, expected) in [
        (55, "c1c8bbdc22796e28c0e15163d20899b65621d65a"),
        (56, "c2db330f6083854c99d4b5bfb6e8f29f201be699"),
        (63, "03f09f5b158a7a8cdad920bddc29b81c18a551f5"),
        (64, "0098ba824b5c16427bd7a1122a5a442a25ec644d"),
        (1_000_000, "34aa973cd4c4daa4f61eeb2bdbad27316534016f"),
    ] {
        let mut hash = Sha1::new();
        for _ in 0..length {
            hash.update(b"a");
        }
        assert_eq!(hex(&hash.finish()), expected);
    }
    assert_eq!(
        hex(&object_digest(ObjectFormat::Sha1, b"blob", b"test\n")),
        "9daeafb9864cf43055ae93beb0afd6c7d144bfa4"
    );
}

#[test]
fn runner_retains_leader_until_group_cleanup() {
    let mut b = Budget::new();
    let output = run_command(
        std::process::Command::new("/usr/bin/printf").arg("raw\\0bytes"),
        b"",
        &mut b,
        false,
    )
    .unwrap();
    assert_eq!(output.stdout, b"raw\0bytes");
    assert_eq!(
        b.process_events,
        ["spawn", "exit-nowait", "kill-group", "wait"]
    );
    assert_eq!(b.counters.child_launches, 1);
    assert_eq!(b.counters.observed_process_bytes, 9);
    assert_eq!(b.counters.uncertain_process_reservation_bytes, 0);
}

#[test]
fn runner_counts_stderr_and_concurrent_input_without_exposing_diagnostics() {
    let mut b = Budget::new();
    let input = b"input\0with\nraw framing";
    let output = run_command(
        &mut std::process::Command::new("/usr/bin/cat"),
        input,
        &mut b,
        false,
    )
    .unwrap();
    assert_eq!(output.stdout, input);
    assert_eq!(b.counters.observed_process_input_bytes, input.len() as u64);
    assert_eq!(b.counters.observed_process_bytes, input.len() as u64);
    let mut b = Budget::new();
    b.counters.charged_read_bytes = MAX_CHARGED_BYTES - 4;
    // Owned test child only. Production admits only the literal Git command set.
    let result = run_command(
        std::process::Command::new("/bin/sh").args(["-c", "printf secret-diagnostic >&2"]),
        b"",
        &mut b,
        false,
    );
    assert!(result.is_err());
    assert_eq!(b.counters.observed_process_bytes, 4);
    assert!(b.process_events.ends_with(&["kill-group", "wait"]));
}

#[test]
fn git_process_and_input_limits() {
    let mut b = Budget::new();
    b.counters.reserved_child_slots = 96;
    assert!(run_command(
        &mut std::process::Command::new("/usr/bin/printf"),
        b"",
        &mut b,
        false
    )
    .is_err());
    assert_eq!(b.counters.child_launches, 0);
    let mut b = Budget::new();
    b.counters.charged_read_bytes = MAX_CHARGED_BYTES - 4;
    assert!(run_command(
        std::process::Command::new("/usr/bin/printf").arg("12345678"),
        b"",
        &mut b,
        false
    )
    .is_err());
    assert_eq!(b.counters.observed_process_bytes, 4);
    assert_eq!(b.counters.child_launches, 1);
    assert!(b.process_events.ends_with(&["kill-group", "wait"]));
}

fn index_fixture(version: u32, extended: Option<u16>, extension: &[u8]) -> Vec<u8> {
    let mut bytes = b"DIRC".to_vec();
    bytes.extend(version.to_be_bytes());
    bytes.extend(1u32.to_be_bytes());
    let start = bytes.len();
    let mut stat = [0u8; 40];
    stat[24..28].copy_from_slice(&0o100644u32.to_be_bytes());
    bytes.extend(stat);
    bytes.extend([1u8; 20]);
    bytes.extend((1u16 | if extended.is_some() { 0x4000 } else { 0 }).to_be_bytes());
    if let Some(flags) = extended {
        bytes.extend(flags.to_be_bytes());
    }
    bytes.extend(b"a\0");
    while !(bytes.len() - start).is_multiple_of(8) {
        bytes.push(0);
    }
    bytes.extend(extension);
    let checksum = ObjectFormat::Sha1.hash(&bytes);
    bytes.extend(checksum);
    bytes
}

#[test]
fn index_v2_v3_extensions_and_checksums() {
    for (version, flags) in [(2, None), (3, Some(0x4000))] {
        let bytes = index_fixture(version, flags, b"");
        let entries = parse_index(&bytes, ObjectFormat::Sha1).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries.values().next().unwrap().skip_worktree,
            flags.is_some()
        );
        let mut bad = bytes.clone();
        bad[20] ^= 1;
        assert!(parse_index(&bad, ObjectFormat::Sha1).is_err());
    }
    for (version, flags, extension) in [
        (4, None, b"".as_slice()),
        (2, Some(0x4000), b""),
        (3, Some(0x2000), b""),
        (3, Some(1), b""),
        (2, None, b"UNTR\0\0\0\0"),
        (2, None, b"TREE\0\0\0\x01x"),
    ] {
        assert!(parse_index(
            &index_fixture(version, flags, extension),
            ObjectFormat::Sha1
        )
        .is_err());
    }
    // Valid invalidated cache-tree node: no OID when entry_count is negative.
    assert!(parse_index(
        &index_fixture(2, None, b"TREE\0\0\0\x06\0-1 0\n"),
        ObjectFormat::Sha1
    )
    .is_ok());
}

#[test]
fn native_anchor_paths_reject_git_trimming_ambiguity() {
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt, path::Path};
    for raw in [
        b"/tmp/private\n".as_slice(),
        b"/tmp/private\r",
        b"/tmp/private ",
        b"/tmp/a\nb",
        b"/tmp/../private",
        b"relative",
    ] {
        assert!(native_anchor_path(Path::new(OsStr::from_bytes(raw))).is_err());
    }
    assert!(native_anchor_path(Path::new("/tmp/ordinary space/private")).is_ok());
    // This is only an administrative transport restriction, not path folding.
    assert!(RawPath::from_bytes(b"payload/\xff\n\t").is_ok());
}

#[test]
fn git_byte_protocols_reject_ambiguity() {
    let oid = vec![b'1'; 40];
    let mut stage = b"100644 ".to_vec();
    stage.extend(&oid);
    stage.extend(b" 0\t-x\xff\n\t\0");
    let parsed = parse_stage(&stage, ObjectFormat::Sha1).unwrap();
    assert!(parsed.contains_key(&crate::disposal::RawPath::from_bytes(b"-x\xff\n\t").unwrap()));
    assert!(parse_stage(&[stage.clone(), stage.clone()].concat(), ObjectFormat::Sha1).is_err());
    assert!(parse_stage(&stage[..stage.len() - 1], ObjectFormat::Sha1).is_err());
    let requested = vec![crate::disposal::RawPath::from_bytes(b"cache/a\n").unwrap()];
    assert!(
        parse_ignored(
            b".gitignore\0"
                .iter()
                .copied()
                .chain(b"1\0cache/\0./cache/a\n\0".iter().copied())
                .collect::<Vec<_>>()
                .as_slice(),
            &requested
        )
        .unwrap()[&requested[0]]
    );
    assert!(parse_ignored(b"\0\0\0other\0", &requested).is_err());
    assert!(parse_ignored(b"\0\0\0cache/a\n\0extra\0", &requested).is_err());
    assert!(parse_ignored(b"\0\0\0./cache/a\n\0extra\0", &requested).is_err());
    let payload = b"binary\0\n123 blob 9\n";
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let oid = hex(&object_digest(format, b"blob", payload));
        let mut wire = format!("{oid} blob {}\n", payload.len()).into_bytes();
        wire.extend(payload);
        wire.push(b'\n');
        let expected = vec![(oid.as_bytes().to_vec(), payload.len() as u64)];
        assert!(parse_blobs(&wire, &expected, format).is_ok());
        let mut corrupt = wire.clone();
        corrupt[oid.len() + 8] ^= 1;
        assert!(parse_blobs(&corrupt, &expected, format).is_err());
        wire.push(b'\n');
        assert!(parse_blobs(&wire, &expected, format).is_err());
    }
}

#[test]
fn ignored_protocol_requires_exact_prefixed_raw_echoes() {
    let paths = [
        b":(glob)tracked".as_slice(),
        b"cache/track?d",
        b"cache/*",
        b"cache/[t]racked",
        b"cache/\xff\n\t",
        b"cache/empty",
    ];
    let requested: Vec<_> = paths
        .iter()
        .map(|p| RawPath::from_bytes(p).unwrap())
        .collect();
    let mut wire = Vec::new();
    for (i, path) in paths.iter().enumerate() {
        wire.extend_from_slice(if i == 0 { b"\0\0\0" } else { b".gitignore\0" });
        if i != 0 {
            wire.extend_from_slice(b"1\0cache/\0");
        }
        wire.extend_from_slice(b"./");
        wire.extend_from_slice(path);
        wire.push(0);
    }
    let parsed = parse_ignored(&wire, &requested).unwrap();
    for (i, path) in requested.iter().enumerate() {
        assert_eq!(parsed[path], i != 0);
    }
    let requested = [RawPath::from_bytes(b"cache/a").unwrap()];
    for echo in [
        b"cache/a".as_slice(), // missing deliberate prefix
        b"././cache/a",
        b"./cache/../cache/a",
        b"./cache//a",
        b"./cache/a/",
        b"./other",
        b"/cache/a",
        b"./",
    ] {
        let mut wire = b"\0\0\0".to_vec();
        wire.extend_from_slice(echo);
        wire.push(0);
        assert!(parse_ignored(&wire, &requested).is_err());
    }
    let record = b"\0\0\0./cache/a\0";
    let duplicate = [record.as_slice(), record.as_slice()].concat();
    assert!(parse_ignored(&duplicate, &requested).is_err()); // extra response
    let two = [
        requested[0].clone(),
        RawPath::from_bytes(b"cache/b").unwrap(),
    ];
    assert!(parse_ignored(&duplicate, &two).is_err()); // wrong second response
    assert!(parse_ignored(record, &two).is_err()); // missing response
    let duplicate_requests = [requested[0].clone(), requested[0].clone()];
    assert!(parse_ignored(&duplicate, &duplicate_requests).is_err());
    assert!(
        !parse_ignored(b".gitignore\x001\0!cache/a\0./cache/a\0", &requested).unwrap()
            [&requested[0]]
    );
}

#[test]
fn canonical_digest_binds_all_evidence() {
    let p = crate::disposal::validate(crate::disposal::PolicyDocument {
        format: 1,
        policies: vec![],
    })
    .unwrap();
    let mut b = Budget::new();
    let first = finish_observation(&p, b"context", b"evidence", vec![], vec![], None, &b).unwrap();
    let same = finish_observation(&p, b"context", b"evidence", vec![], vec![], None, &b).unwrap();
    assert_eq!(first.digest(), same.digest());
    for (context, evidence, reason) in [
        (b"changed".as_slice(), b"evidence".as_slice(), None),
        (b"context", b"changed", None),
        (b"context", b"evidence", Some(IncompleteReason::Changed)),
    ] {
        let other = finish_observation(&p, context, evidence, vec![], vec![], reason, &b).unwrap();
        assert_ne!(first.digest(), other.digest());
    }
    b.counters.child_launches = 1;
    assert_ne!(
        first.digest(),
        finish_observation(&p, b"context", b"evidence", vec![], vec![], None, &b)
            .unwrap()
            .digest()
    );
}

use super::filesystem::{self, Boundary, Event, Identity, SystemBoundary};
use super::*;
use crate as work_cli_api;
use std::{fs, os::unix::fs::symlink, time::Duration};
#[path = "../tests/support/inspection_fixture.rs"]
mod fixture;
use fixture::InspectionFixture;

#[test]
fn context_change_is_incomplete_without_inspection_mutations() {
    let mut f = fixture::ManagedFixture::new("sha1", "2");
    let policies = crate::disposal::validate(crate::disposal::PolicyDocument {
        format: 1,
        policies: vec![],
    })
    .unwrap();
    let checkout = f.allocation.checkout;
    let events = f.store.pending_events(100).unwrap();
    let mut reached = false;
    let mut change = |store: &mut Store| {
        reached = true;
        assert!(
            store.conn.is_autocommit(),
            "SQL must end before observation I/O"
        );
        store
            .conn
            .execute(
                "UPDATE checkouts SET owner='external-change' WHERE id=?1",
                [checkout.to_string()],
            )
            .unwrap();
    };
    let observation = inspect_inner(&mut f.store, checkout, &policies, Some(&mut change)).unwrap();
    assert!(
        reached,
        "initial inspection refused before context mutation: reasons={:?}, counters={:?}",
        observation.reasons(),
        observation.counters()
    );
    assert_eq!(observation.reasons(), [IncompleteReason::ContextConflict]);
    assert_eq!(events, f.store.pending_events(100).unwrap());
    let owner: String = f
        .store
        .conn
        .query_row(
            "SELECT owner FROM checkouts WHERE id=?1",
            [checkout.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        owner, "external-change",
        "inspection must not repair external context"
    );
    let writers: i64 = f
        .store
        .conn
        .query_row("SELECT count(*) FROM writers", [], |r| r.get(0))
        .unwrap();
    assert_eq!(writers, 0);
}

#[test]
fn active_sql_or_transaction_is_refused_before_io() {
    let mut f = fixture::ManagedFixture::new("sha1", "2");
    let policies = crate::disposal::validate(crate::disposal::PolicyDocument {
        format: 1,
        policies: vec![],
    })
    .unwrap();
    let phase = f.store.sql_phase();
    let o = f.inspect(&policies);
    assert_eq!(o.reasons(), [IncompleteReason::ContextUnavailable]);
    assert_eq!(o.counters().child_launches, 0);
    drop(phase);
    f.store.conn.execute_batch("BEGIN;").unwrap();
    let o = f.inspect(&policies);
    assert_eq!(o.reasons(), [IncompleteReason::ContextUnavailable]);
    assert_eq!(o.counters().observed_file_bytes, 0);
    assert!(!f.store.conn.is_autocommit());
    f.store.conn.execute_batch("ROLLBACK;").unwrap();
}

#[test]
fn byte_identical_registration_replacement_invalidates_observation() {
    let mut f = fixture::ManagedFixture::new("sha1", "2");
    let policies = crate::disposal::validate(crate::disposal::PolicyDocument {
        format: 1,
        policies: vec![],
    })
    .unwrap();
    let path = f.private().join("gitdir");
    let bytes = fs::read(&path).unwrap();
    let mut reached = false;
    let mut replace = |_: &mut Store| {
        reached = true;
        fs::rename(&path, path.with_extension("old")).unwrap();
        fs::write(&path, &bytes).unwrap();
    };
    let o = inspect_inner(
        &mut f.store,
        f.allocation.checkout,
        &policies,
        Some(&mut replace),
    )
    .unwrap();
    assert!(
        reached,
        "initial inspection refused before registration replacement: reasons={:?}, counters={:?}",
        o.reasons(),
        o.counters()
    );
    assert_eq!(o.coverage(), Coverage::Incomplete);
    assert!(o.reasons().contains(&IncompleteReason::Changed));
}

#[test]
fn private_refs_identity_and_empty_names_are_rechecked() {
    for (case, reason) in [
        ("replacement", IncompleteReason::Changed),
        ("new-name", IncompleteReason::UnsupportedGit),
    ] {
        let mut f = fixture::ManagedFixture::new("sha1", "2");
        let policies = crate::disposal::validate(crate::disposal::PolicyDocument {
            format: 1,
            policies: vec![],
        })
        .unwrap();
        let refs = f.private().join("refs");
        assert!(fs::symlink_metadata(&refs).unwrap().is_dir());
        assert!(fs::read_dir(&refs).unwrap().next().is_none());
        let mut reached = false;
        let mut change = |_: &mut Store| {
            reached = true;
            match case {
                "replacement" => {
                    fs::rename(&refs, refs.with_extension("old")).unwrap();
                    fs::create_dir(&refs).unwrap();
                }
                "new-name" => fs::create_dir(refs.join("bisect")).unwrap(),
                _ => unreachable!(),
            }
        };
        let o = inspect_inner(
            &mut f.store,
            f.allocation.checkout,
            &policies,
            Some(&mut change),
        )
        .unwrap();
        assert!(
            reached,
            "{case}: initial inspection refused: reasons={:?}, counters={:?}",
            o.reasons(),
            o.counters()
        );
        assert_eq!(o.coverage(), Coverage::Incomplete, "{case}");
        // A new name is refused during repeated admission; an empty replacement
        // remains structurally admissible but fails the retained identity check.
        assert!(o.reasons().contains(&reason), "{case}");
    }
}

#[test]
fn tracked_git_mode_equivalence_uses_owner_execute_only() {
    use std::os::unix::fs::PermissionsExt;
    let f = InspectionFixture::directory();
    let payload = b"tracked\n";
    f.write(b"tracked", payload);
    let path = RawPath::from_bytes(b"tracked").unwrap();
    let oid = object_digest(ObjectFormat::Sha1, b"blob", payload);
    let policies = crate::disposal::validate(crate::disposal::PolicyDocument {
        format: 1,
        policies: vec![],
    })
    .unwrap();
    // Private classification test, not synthetic authority for full inspection.
    for (indexed_mode, actual_mode, changed) in [
        (0o100755, 0o654, true), // group execute cannot substitute for owner execute
        (0o100755, 0o744, false),
        (0o100755, 0o755, false),
        (0o100644, 0o654, false),
        (0o100644, 0o645, false), // other execute is likewise irrelevant to Git mode
        (0o100644, 0o744, true),
    ] {
        fs::set_permissions(f.path(b"tracked"), fs::Permissions::from_mode(actual_mode)).unwrap();
        let census =
            filesystem::walk(&f.checkout, &mut Budget::new(), &mut SystemBoundary).unwrap();
        let index = BTreeMap::from([(
            path.clone(),
            IndexEntry {
                mode: indexed_mode,
                oid: oid.clone(),
                assume_unchanged: false,
                skip_worktree: false,
            },
        )]);
        let proof = GitProof {
            tree: index.clone(),
            index,
            ignored: BTreeMap::new(),
            blobs: BTreeMap::from([(
                oid.clone(),
                (payload.len() as u64, Sha256::digest(payload).into()),
            )]),
            canonical: vec![],
        };
        let (entries, findings) = classify(&census, &proof, &policies);
        assert_eq!(
            findings
                .iter()
                .any(|f| f.path == path && f.kind == FindingKind::TrackedContent),
            changed,
            "index={indexed_mode:o}, actual={actual_mode:o}"
        );
        assert_eq!(entries[0].mode & 0o7777, actual_mode);
        assert_eq!(census.entries[0].mode() & 0o7777, actual_mode);
        assert!(!findings.iter().any(|f| f.kind == FindingKind::StagedChange));
    }
}

#[test]
fn descriptor_reopen_never_opens_a_replacement() {
    struct Replace {
        file: std::path::PathBuf,
        opened: usize,
        original: Option<u64>,
    }
    impl Boundary for Replace {
        fn event(
            &mut self,
            event: Event,
            _: &[u8],
            identity: Option<&Identity>,
        ) -> Result<(), IncompleteReason> {
            if event == Event::BeforeDataOpen {
                self.original = Some(identity.unwrap().inode);
                fs::rename(&self.file, self.file.with_extension("old")).unwrap();
                fs::write(&self.file, b"replacement").unwrap();
            }
            if event == Event::DataOpened {
                self.opened += 1;
                assert_eq!(Some(identity.unwrap().inode), self.original);
            }
            Ok(())
        }
    }
    let f = InspectionFixture::directory();
    f.write(b"a", b"original");
    let mut hook = Replace {
        file: f.path(b"a"),
        opened: 0,
        original: None,
    };
    let mut budget = Budget::new();
    assert_eq!(
        filesystem::walk(&f.checkout, &mut budget, &mut hook).err(),
        Some(IncompleteReason::Changed)
    );
    assert_eq!(hook.opened, 1);
    assert_eq!(budget.counters.observed_file_bytes, 0);
}

#[test]
fn unsupported_resolution_is_incomplete() {
    // Injected resolution/mount/EACCES boundary, not real OS qualification.
    struct Reject {
        reason: IncompleteReason,
        opens: usize,
        fired: bool,
    }
    impl Boundary for Reject {
        fn event(
            &mut self,
            e: Event,
            _: &[u8],
            _: Option<&Identity>,
        ) -> Result<(), IncompleteReason> {
            if e == Event::BeforeChildOpen {
                self.fired = true;
                return Err(self.reason);
            }
            if e == Event::BeforeDataOpen {
                self.opens += 1;
            }
            Ok(())
        }
    }
    let f = InspectionFixture::directory();
    f.write(b"a", b"abc");
    for reason in [
        IncompleteReason::UnsupportedResolution,
        IncompleteReason::MountCrossing,
        IncompleteReason::Unreadable,
    ] {
        let mut h = Reject {
            reason,
            opens: 0,
            fired: false,
        };
        assert_eq!(
            filesystem::walk(&f.checkout, &mut Budget::new(), &mut h).err(),
            Some(reason)
        );
        assert!(h.fired, "injected boundary was not reached");
        assert_eq!(h.opens, 0);
    }
    for errno in [
        rustix::io::Errno::NOSYS,
        rustix::io::Errno::INVAL,
        rustix::io::Errno::LOOP,
    ] {
        assert_eq!(
            filesystem::os_error(errno),
            IncompleteReason::UnsupportedResolution
        );
    }
    assert_eq!(
        filesystem::os_error(rustix::io::Errno::XDEV),
        IncompleteReason::MountCrossing
    );
    assert_eq!(
        filesystem::os_error(rustix::io::Errno::ACCESS),
        IncompleteReason::Unreadable
    );
}

#[test]
fn budget_boundaries_are_explicit() {
    for remaining in [
        DIRECTORY_BUFFER_BYTES - 1,
        DIRECTORY_BUFFER_BYTES,
        DIRECTORY_BUFFER_BYTES + 1,
    ] {
        // EOF, error and ordinary entry all pay the FULL refill reservation.
        for outcome in [None, Some(Err(())), Some(Ok(()))] {
            let mut b = Budget::new();
            b.counters.charged_read_bytes = MAX_CHARGED_BYTES - remaining as u64;
            let before = b.counters.charged_read_bytes;
            let mut calls = 0;
            let result = directory_next(&mut b, true, || {
                calls += 1;
                outcome
            });
            if remaining < DIRECTORY_BUFFER_BYTES {
                assert_eq!(result.err(), Some(IncompleteReason::ReadBudget));
                assert_eq!(calls, 0);
            } else {
                assert!(result.is_ok());
                assert_eq!(calls, 1);
                assert_eq!(
                    b.counters.charged_read_bytes - before,
                    DIRECTORY_BUFFER_BYTES as u64
                );
                assert_eq!(
                    b.counters.directory_reserved_bytes,
                    DIRECTORY_BUFFER_BYTES as u64
                );
                assert_eq!(b.counters.observed_file_bytes, 0);
                assert_eq!(
                    directory_next(&mut b, true, || {
                        calls += 1;
                        None::<()>
                    })
                    .err(),
                    Some(IncompleteReason::ReadBudget)
                );
                assert_eq!(calls, 1);
            }
        }
    }
    let mut b = Budget::new();
    directory_next(&mut b, false, || Some(())).unwrap();
    assert_eq!(b.counters.directory_reserved_bytes, 0);
    for used in [MAX_ENTRIES - 1, MAX_ENTRIES, MAX_ENTRIES + 1] {
        let mut b = Budget::new();
        b.counters.entries = used;
        assert_eq!(b.entry().is_ok(), used < MAX_ENTRIES);
    }
    for elapsed in [
        Duration::from_secs(29),
        Duration::from_secs(30),
        Duration::from_secs(31),
    ] {
        let mut b = Budget::new();
        b.test_elapsed = Some(elapsed);
        assert_eq!(b.check().is_ok(), elapsed < Duration::from_secs(30));
    }
    for length in [MAX_FILE_BYTES - 1, MAX_FILE_BYTES, MAX_FILE_BYTES + 1] {
        assert_eq!(
            Budget::new().file_length(length).is_ok(),
            length <= MAX_FILE_BYTES
        );
    }
    for used in [
        MAX_OUTPUT_BYTES - TERMINAL_RESERVE - 1,
        MAX_OUTPUT_BYTES - TERMINAL_RESERVE,
        MAX_OUTPUT_BYTES - TERMINAL_RESERVE + 1,
    ] {
        let mut b = Budget::new();
        b.counters.retained_output_bytes = used;
        assert_eq!(
            b.output(1).is_ok(),
            used < MAX_OUTPUT_BYTES - TERMINAL_RESERVE
        );
    }
    let mut b = Budget::new();
    b.counters.charged_read_bytes = MAX_CHARGED_BYTES - 3;
    let ticket = b.reserve_file_read(3).unwrap();
    b.finish_file_read(ticket, 2).unwrap();
    assert_eq!(b.counters.observed_file_bytes, 2);
    assert_eq!(b.counters.charged_read_bytes, MAX_CHARGED_BYTES - 1);
    let ticket = b.reserve_file_read(1).unwrap();
    b.finish_file_read(ticket, 1).unwrap();
    assert!(b.reserve_file_read(1).is_err()); // Even EOF lookahead needs allowance.
    assert_eq!(b.counters.observed_file_bytes, 3);
    assert!(b.check().is_err()); // Exhaustion is sticky; no subsequent work.
}

#[test]
fn process_budget_types_do_not_launch_children() {
    for used in [95, 96, 97] {
        let mut b = Budget::new();
        b.counters.reserved_child_slots = used;
        assert_eq!(b.reserve_process(0, 0).is_ok(), used < 96);
        assert_eq!(b.counters.child_launches, 0);
    }
    for bytes in [1024 * 1024 - 1, 1024 * 1024, 1024 * 1024 + 1] {
        assert_eq!(
            Budget::new().reserve_process(bytes, 0).is_ok(),
            bytes <= 1024 * 1024
        );
    }
    for bytes in [32 * 1024 - 1, 32 * 1024, 32 * 1024 + 1] {
        assert_eq!(
            Budget::new().reserve_process(0, bytes).is_ok(),
            bytes <= 32 * 1024
        );
    }
    for used in [8 * 1024 * 1024 - 1, 8 * 1024 * 1024, 8 * 1024 * 1024 + 1] {
        let mut b = Budget::new();
        b.counters.reserved_process_input_bytes = used;
        assert_eq!(b.reserve_process(1, 0).is_ok(), used < 8 * 1024 * 1024);
    }
    let mut b = Budget::new();
    b.test_elapsed = Some(Duration::from_secs(29));
    assert_eq!(
        b.reserve_process(0, 0).unwrap().maximum_duration,
        Duration::from_secs(1)
    );
    let mut b = Budget::new();
    b.test_elapsed = Some(Duration::ZERO);
    assert_eq!(
        b.reserve_process(0, 0).unwrap().maximum_duration,
        Duration::from_secs(2)
    );
    b.test_elapsed = Some(Duration::from_secs(30));
    assert!(b.reserve_process(0, 0).is_err());
    assert_eq!(b.counters.child_launches, 0);
    assert_eq!(b.counters.observed_process_bytes, 0);
}

#[test]
fn read_errors_keep_conservative_reservations_and_stop_further_reads() {
    struct Fault(usize);
    impl std::io::Read for Fault {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            self.0 += 1;
            Err(std::io::Error::other("injected read failure"))
        }
    }
    let mut b = Budget::new();
    let mut fault = Fault(0);
    let mut buf = [0; 17];
    assert_eq!(
        read_chunk(&mut fault, &mut buf, &mut b).err(),
        Some(IncompleteReason::Io)
    );
    assert_eq!(b.counters.observed_file_bytes, 0);
    assert_eq!(b.counters.uncertain_file_reservation_bytes, 17);
    assert_eq!(b.counters.charged_read_bytes, 17);
    assert!(read_chunk(&mut fault, &mut buf, &mut b).is_err());
    assert_eq!(fault.0, 1);
}

#[test]
fn census_rechecks_names_and_anchors() {
    struct Change {
        path: std::path::PathBuf,
        when: Event,
        done: bool,
    }
    impl Boundary for Change {
        fn event(
            &mut self,
            e: Event,
            _: &[u8],
            _: Option<&Identity>,
        ) -> Result<(), IncompleteReason> {
            if e == self.when && !self.done {
                self.done = true;
                if e == Event::BeforeAnchorRecheck {
                    fs::rename(&self.path, self.path.with_extension("moved")).unwrap();
                    fs::create_dir(&self.path).unwrap();
                } else {
                    fs::write(self.path.join("late"), b"late").unwrap();
                }
            }
            Ok(())
        }
    }
    for when in [Event::BeforeReenumerate, Event::BeforeAnchorRecheck] {
        let f = InspectionFixture::directory();
        f.write(b"a", b"abc");
        let mut hook = Change {
            path: f.checkout.clone(),
            when,
            done: false,
        };
        assert_eq!(
            filesystem::walk(&f.checkout, &mut Budget::new(), &mut hook).err(),
            Some(IncompleteReason::Changed)
        );
        assert!(hook.done);
    }
}

#[test]
fn outside_parent_sibling_churn_preserves_private_census() {
    struct Siblings {
        parent: std::path::PathBuf,
        fired: bool,
    }
    impl Boundary for Siblings {
        fn event(
            &mut self,
            e: Event,
            _: &[u8],
            _: Option<&Identity>,
        ) -> Result<(), IncompleteReason> {
            if e == Event::BeforeAnchorRecheck && !self.fired {
                self.fired = true;
                fs::write(self.parent.join("outside-file"), b"unrelated").unwrap();
                fs::create_dir(self.parent.join("outside-directory")).unwrap();
            }
            Ok(())
        }
    }
    let f = InspectionFixture::directory();
    f.write(b"a", b"abc");
    let mut h = Siblings {
        parent: f.temp.path().to_owned(),
        fired: false,
    };
    let mut b = Budget::new();
    let census = filesystem::walk(&f.checkout, &mut b, &mut h).unwrap();
    assert!(h.fired);
    assert_eq!(census.entries.len(), 1);
    assert_eq!(census.entries[0].path.as_bytes(), b"a");
    let expected: [u8; 32] = Sha256::digest(b"abc").into();
    assert_eq!(census.entries[0].content_sha256, Some(expected));
    assert_eq!(b.counters.observed_file_bytes, 3);
    assert_eq!(b.counters.child_launches, 0);
}

#[test]
fn outside_ancestor_binding_changes_still_refuse() {
    use std::os::unix::fs::PermissionsExt;
    struct Replace {
        ancestor: std::path::PathBuf,
        kind: &'static str,
        fired: bool,
    }
    impl Boundary for Replace {
        fn event(
            &mut self,
            e: Event,
            _: &[u8],
            _: Option<&Identity>,
        ) -> Result<(), IncompleteReason> {
            if e == Event::BeforeAnchorRecheck && !self.fired {
                self.fired = true;
                if self.kind == "permissions" {
                    fs::set_permissions(&self.ancestor, fs::Permissions::from_mode(0o700)).unwrap();
                } else {
                    let moved = self.ancestor.with_extension("moved");
                    fs::rename(&self.ancestor, &moved).unwrap();
                    match self.kind {
                        "directory" => fs::create_dir(&self.ancestor).unwrap(),
                        "symlink" => symlink(&moved, &self.ancestor).unwrap(),
                        "file" => fs::write(&self.ancestor, b"not a directory").unwrap(),
                        _ => unreachable!(),
                    }
                }
            }
            Ok(())
        }
    }
    for kind in ["directory", "symlink", "file", "permissions"] {
        let temp = tempfile::tempdir().unwrap();
        let ancestor = temp.path().join("route");
        let checkout = ancestor.join("checkout");
        fs::create_dir_all(&checkout).unwrap();
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(checkout.join("a"), b"abc").unwrap();
        let mut h = Replace {
            ancestor,
            kind,
            fired: false,
        };
        assert_eq!(
            filesystem::walk(&checkout, &mut Budget::new(), &mut h).err(),
            Some(IncompleteReason::Changed),
            "{kind}"
        );
        assert!(h.fired, "ancestor mutation was not reached: {kind}");
    }
}

#[test]
fn final_recheck_still_covers_root_and_descendant_contents() {
    struct Change {
        checkout: std::path::PathBuf,
        kind: &'static str,
        fired: bool,
    }
    impl Boundary for Change {
        fn event(
            &mut self,
            e: Event,
            _: &[u8],
            _: Option<&Identity>,
        ) -> Result<(), IncompleteReason> {
            if e == Event::BeforeAnchorRecheck && !self.fired {
                self.fired = true;
                match self.kind {
                    "root" => fs::create_dir(self.checkout.join("late")).unwrap(),
                    "directory" => fs::create_dir(self.checkout.join("sub/late")).unwrap(),
                    "file" => {
                        fs::write(self.checkout.join("sub/a"), b"changed and longer").unwrap()
                    }
                    _ => unreachable!(),
                }
            }
            Ok(())
        }
    }
    for kind in ["root", "directory", "file"] {
        let f = InspectionFixture::directory();
        fs::create_dir(f.path(b"sub")).unwrap();
        f.write(b"sub/a", b"abc");
        let mut h = Change {
            checkout: f.checkout.clone(),
            kind,
            fired: false,
        };
        assert_eq!(
            filesystem::walk(&f.checkout, &mut Budget::new(), &mut h).err(),
            Some(IncompleteReason::Changed),
            "{kind}"
        );
        assert!(h.fired, "final mutation was not reached: {kind}");
    }
}

#[test]
fn raw_names_and_ignored_descendants_are_all_observed() {
    let f = InspectionFixture::linked();
    let names = f.raw_payloads();
    let mut b = Budget::new();
    let census = filesystem::walk(&f.checkout, &mut b, &mut SystemBoundary).unwrap();
    for name in names {
        let found = census
            .entries
            .iter()
            .find(|e| e.path.as_bytes() == name)
            .unwrap();
        let expected: [u8; 32] = sha2::Sha256::digest(b"abc").into();
        assert_eq!(found.content_sha256, Some(expected));
    }
    assert!(census
        .entries
        .iter()
        .any(|e| e.path.as_bytes() == b"cache/empty"));
    assert!(census.entries.iter().any(|e| e.path.as_bytes() == b".git")); // ordinary file, NOT administrative exemption
    assert!(census.entries.windows(2).all(|p| p[0].path < p[1].path));
    assert!(b.counters.directory_reserved_bytes >= (DIRECTORY_BUFFER_BYTES * 4) as u64);
    assert!(b.counters.observed_file_bytes > 0);
    assert_eq!(
        b.counters.charged_read_bytes,
        b.counters.observed_file_bytes + b.counters.directory_reserved_bytes
    );
    assert_eq!(b.counters.child_launches, 0); // Fixture Git is not inspection Git.
}

#[test]
fn stable_links_specials_and_nested_git_never_reach_data_open() {
    #[derive(Default)]
    struct Count {
        opens: usize,
        rejected: Option<(Vec<u8>, IncompleteReason)>,
        anchor_rejected: Option<(Vec<u8>, IncompleteReason)>,
    }
    impl Boundary for Count {
        fn event(
            &mut self,
            e: Event,
            _: &[u8],
            _: Option<&Identity>,
        ) -> Result<(), IncompleteReason> {
            if e == Event::BeforeDataOpen {
                self.opens += 1;
            }
            Ok(())
        }
        fn rejected(&mut self, path: &[u8], reason: IncompleteReason) {
            self.rejected = Some((path.to_vec(), reason));
        }
        fn anchor_rejected(&mut self, name: &[u8], reason: IncompleteReason) {
            self.anchor_rejected = Some((name.to_vec(), reason));
        }
    }
    for case in ["symlink", "hardlink", "fifo", "socket", "nested"] {
        let f = InspectionFixture::directory();
        let mut socket = None;
        match case {
            "symlink" => symlink("absent", f.path(b"a")).unwrap(),
            "hardlink" => {
                fs::write(f.temp.path().join("outside"), b"x").unwrap();
                fs::hard_link(f.temp.path().join("outside"), f.path(b"a")).unwrap();
            }
            "fifo" => rustix::fs::mknodat(
                rustix::fs::CWD,
                f.path(b"a"),
                rustix::fs::FileType::Fifo,
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
                0,
            )
            .unwrap(),
            "socket" => {
                socket = Some(std::os::unix::net::UnixListener::bind(f.path(b"a")).unwrap())
            }
            "nested" => fs::create_dir_all(f.path(b"a/.git")).unwrap(),
            _ => unreachable!(),
        }
        let (path, reason) = match case {
            "symlink" => (b"a".as_slice(), IncompleteReason::Symlink),
            "hardlink" => (b"a".as_slice(), IncompleteReason::Hardlink),
            "fifo" | "socket" => (b"a".as_slice(), IncompleteReason::SpecialFile),
            "nested" => (b"a/.git".as_slice(), IncompleteReason::NestedGit),
            _ => unreachable!(),
        };
        let mut h = Count::default();
        assert_eq!(
            filesystem::walk(&f.checkout, &mut Budget::new(), &mut h).err(),
            Some(reason),
            "{case}"
        );
        assert_eq!(
            h.rejected,
            Some((path.to_vec(), reason)),
            "decision not reached: {case}"
        );
        assert_eq!(h.opens, 0, "{case}");
        drop(socket);
    }
    let f = InspectionFixture::directory();
    symlink(&f.checkout, f.temp.path().join("alias")).unwrap();
    let mut h = Count::default();
    let reason = filesystem::walk(&f.temp.path().join("alias"), &mut Budget::new(), &mut h)
        .err()
        .unwrap();
    // O_PATH|DIRECTORY|NOFOLLOW may report ENOTDIR, or resolution ELOOP.
    // Both must come from the actual alias component, not earlier proc/setup.
    assert!(matches!(
        reason,
        IncompleteReason::Changed | IncompleteReason::UnsupportedResolution
    ));
    assert_eq!(h.anchor_rejected, Some((b"alias".to_vec(), reason)));
    assert_eq!(h.opens, 0);
}

#[test]
fn filesystem_only_empty_file_positive_and_main_git_refusal() {
    let f = InspectionFixture::directory();
    f.write(b"empty", b"");
    let mut b = Budget::new();
    let census = filesystem::walk(&f.checkout, &mut b, &mut SystemBoundary).unwrap();
    let expected: [u8; 32] = Sha256::digest(b"").into();
    assert_eq!(census.entries.len(), 1);
    assert_eq!(census.entries[0].content_sha256, Some(expected));
    assert_eq!(b.counters.observed_file_bytes, 0);
    assert_eq!(b.counters.uncertain_file_reservation_bytes, 0);
    assert_eq!(
        b.counters.charged_read_bytes,
        b.counters.directory_reserved_bytes
    );
    fs::create_dir(f.path(b".git")).unwrap();
    assert_eq!(
        filesystem::walk(&f.checkout, &mut Budget::new(), &mut SystemBoundary).err(),
        Some(IncompleteReason::GitMetadataUnproven)
    );
}

#[test]
fn simulated_device_is_rejected_before_data_open() {
    // Injected fstat type only; this is not live-device/OS qualification.
    struct Device {
        opens: usize,
        fired: bool,
        rejected: bool,
    }
    impl Boundary for Device {
        fn child_identity(&mut self, mut i: Identity) -> Identity {
            self.fired = true;
            i.mode = 0o020600;
            i
        }
        fn rejected(&mut self, path: &[u8], reason: IncompleteReason) {
            assert_eq!(path, b"a");
            assert_eq!(reason, IncompleteReason::SpecialFile);
            self.rejected = true;
        }
        fn event(
            &mut self,
            e: Event,
            _: &[u8],
            _: Option<&Identity>,
        ) -> Result<(), IncompleteReason> {
            if e == Event::BeforeDataOpen {
                self.opens += 1;
            }
            Ok(())
        }
    }
    let f = InspectionFixture::directory();
    f.write(b"a", b"abc");
    let mut h = Device {
        opens: 0,
        fired: false,
        rejected: false,
    };
    assert_eq!(
        filesystem::walk(&f.checkout, &mut Budget::new(), &mut h).err(),
        Some(IncompleteReason::SpecialFile)
    );
    assert!(
        h.fired && h.rejected,
        "injected type/rejection was not reached"
    );
    assert_eq!(h.opens, 0);
}

#[test]
fn growth_and_missing_names_invalidate_the_private_census() {
    struct Change {
        path: std::path::PathBuf,
        grow: bool,
        fired: bool,
    }
    impl Boundary for Change {
        fn event(
            &mut self,
            e: Event,
            _: &[u8],
            _: Option<&Identity>,
        ) -> Result<(), IncompleteReason> {
            if e == Event::BeforeFileRead {
                self.fired = true;
                if self.grow {
                    fs::write(&self.path, b"larger than before").unwrap();
                } else {
                    fs::remove_file(&self.path).unwrap();
                }
            }
            Ok(())
        }
    }
    for grow in [true, false] {
        let f = InspectionFixture::directory();
        f.write(b"a", b"abc");
        let mut h = Change {
            path: f.path(b"a"),
            grow,
            fired: false,
        };
        assert_eq!(
            filesystem::walk(&f.checkout, &mut Budget::new(), &mut h).err(),
            Some(IncompleteReason::Changed)
        );
        assert!(h.fired, "growth/unlink mutation was not reached");
    }
}
