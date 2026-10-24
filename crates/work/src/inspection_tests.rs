//! Test source authored before the A2 walker. No execution/RED/GREEN claimed.
use super::*;
use super::filesystem::{self, Boundary, Event, Identity, SystemBoundary};
use std::{fs, os::unix::fs::symlink, time::Duration};
#[path = "../tests/support/inspection_fixture.rs"]
mod fixture;
use fixture::InspectionFixture;

#[test]
fn descriptor_reopen_never_opens_a_replacement() {
    struct Replace { file: std::path::PathBuf, opened: usize, original: Option<u64> }
    impl Boundary for Replace {
        fn event(&mut self, event: Event, _: &[u8], identity: Option<&Identity>) -> Result<(), IncompleteReason> {
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
    let f = InspectionFixture::directory(); f.write(b"a", b"original");
    let mut hook = Replace { file:f.path(b"a"), opened:0, original:None };
    let mut budget = Budget::new();
    assert_eq!(filesystem::walk(&f.checkout, &mut budget, &mut hook).err(), Some(IncompleteReason::Changed));
    assert_eq!(hook.opened, 1);
    assert_eq!(budget.counters.observed_file_bytes, 0);
}

#[test]
fn unsupported_resolution_is_incomplete() {
    // Injected resolution/mount/EACCES boundary, not real OS qualification.
    struct Reject { reason: IncompleteReason, opens: usize, fired: bool }
    impl Boundary for Reject {
        fn event(&mut self, e: Event, _: &[u8], _: Option<&Identity>) -> Result<(), IncompleteReason> {
            if e == Event::BeforeChildOpen { self.fired = true; return Err(self.reason); }
            if e == Event::BeforeDataOpen { self.opens += 1; }
            Ok(())
        }
    }
    let f = InspectionFixture::directory(); f.write(b"a", b"abc");
    for reason in [IncompleteReason::UnsupportedResolution, IncompleteReason::MountCrossing, IncompleteReason::Unreadable] {
        let mut h = Reject { reason, opens:0, fired:false };
        assert_eq!(filesystem::walk(&f.checkout, &mut Budget::new(), &mut h).err(), Some(reason));
        assert!(h.fired, "injected boundary was not reached");
        assert_eq!(h.opens, 0);
    }
    for errno in [rustix::io::Errno::NOSYS, rustix::io::Errno::INVAL, rustix::io::Errno::LOOP] {
        assert_eq!(filesystem::os_error(errno), IncompleteReason::UnsupportedResolution);
    }
    assert_eq!(filesystem::os_error(rustix::io::Errno::XDEV), IncompleteReason::MountCrossing);
    assert_eq!(filesystem::os_error(rustix::io::Errno::ACCESS), IncompleteReason::Unreadable);
}

#[test]
fn budget_boundaries_are_explicit() {
    for remaining in [DIRECTORY_BUFFER_BYTES - 1, DIRECTORY_BUFFER_BYTES, DIRECTORY_BUFFER_BYTES + 1] {
        // EOF, error and ordinary entry all pay the FULL refill reservation.
        for outcome in [None, Some(Err(())), Some(Ok(()))] {
            let mut b = Budget::new();
            b.counters.charged_read_bytes = MAX_CHARGED_BYTES - remaining as u64;
            let before = b.counters.charged_read_bytes;
            let mut calls = 0;
            let result = directory_next(&mut b, true, || { calls += 1; outcome });
            if remaining < DIRECTORY_BUFFER_BYTES {
                assert_eq!(result.err(), Some(IncompleteReason::ReadBudget)); assert_eq!(calls, 0);
            } else {
                assert!(result.is_ok()); assert_eq!(calls, 1);
                assert_eq!(b.counters.charged_read_bytes - before, DIRECTORY_BUFFER_BYTES as u64);
                assert_eq!(b.counters.directory_reserved_bytes, DIRECTORY_BUFFER_BYTES as u64);
                assert_eq!(b.counters.observed_file_bytes, 0);
                assert_eq!(directory_next(&mut b, true, || { calls += 1; None::<()> }).err(), Some(IncompleteReason::ReadBudget));
                assert_eq!(calls, 1);
            }
        }
    }
    let mut b = Budget::new();
    directory_next(&mut b, false, || Some(())).unwrap();
    assert_eq!(b.counters.directory_reserved_bytes, 0);
    for used in [MAX_ENTRIES - 1, MAX_ENTRIES, MAX_ENTRIES + 1] {
        let mut b = Budget::new(); b.counters.entries = used;
        assert_eq!(b.entry().is_ok(), used < MAX_ENTRIES);
    }
    for elapsed in [Duration::from_secs(29), Duration::from_secs(30), Duration::from_secs(31)] {
        let mut b = Budget::new(); b.test_elapsed = Some(elapsed);
        assert_eq!(b.check().is_ok(), elapsed < Duration::from_secs(30));
    }
    for length in [MAX_FILE_BYTES - 1, MAX_FILE_BYTES, MAX_FILE_BYTES + 1] {
        assert_eq!(Budget::new().file_length(length).is_ok(), length <= MAX_FILE_BYTES);
    }
    for used in [MAX_OUTPUT_BYTES - TERMINAL_RESERVE - 1, MAX_OUTPUT_BYTES - TERMINAL_RESERVE, MAX_OUTPUT_BYTES - TERMINAL_RESERVE + 1] {
        let mut b = Budget::new(); b.counters.retained_output_bytes = used;
        assert_eq!(b.output(1).is_ok(), used < MAX_OUTPUT_BYTES - TERMINAL_RESERVE);
    }
    let mut b = Budget::new(); b.counters.charged_read_bytes = MAX_CHARGED_BYTES - 3;
    let ticket = b.reserve_file_read(3).unwrap(); b.finish_file_read(ticket, 2).unwrap();
    assert_eq!(b.counters.observed_file_bytes, 2);
    assert_eq!(b.counters.charged_read_bytes, MAX_CHARGED_BYTES - 1);
    let ticket = b.reserve_file_read(1).unwrap(); b.finish_file_read(ticket, 1).unwrap();
    assert!(b.reserve_file_read(1).is_err()); // Even EOF lookahead needs allowance.
    assert_eq!(b.counters.observed_file_bytes, 3);
    assert!(b.check().is_err()); // Exhaustion is sticky; no subsequent work.
}

#[test]
fn process_budget_types_do_not_launch_children() {
    for used in [95, 96, 97] {
        let mut b = Budget::new(); b.counters.reserved_child_slots = used;
        assert_eq!(b.reserve_process(0, 0).is_ok(), used < 96);
        assert_eq!(b.counters.child_launches, 0);
    }
    for bytes in [1024 * 1024 - 1, 1024 * 1024, 1024 * 1024 + 1] {
        assert_eq!(Budget::new().reserve_process(bytes, 0).is_ok(), bytes <= 1024 * 1024);
    }
    for bytes in [32 * 1024 - 1, 32 * 1024, 32 * 1024 + 1] {
        assert_eq!(Budget::new().reserve_process(0, bytes).is_ok(), bytes <= 32 * 1024);
    }
    for used in [8 * 1024 * 1024 - 1, 8 * 1024 * 1024, 8 * 1024 * 1024 + 1] {
        let mut b = Budget::new(); b.counters.reserved_process_input_bytes = used;
        assert_eq!(b.reserve_process(1, 0).is_ok(), used < 8 * 1024 * 1024);
    }
    let mut b = Budget::new(); b.test_elapsed = Some(Duration::from_secs(29));
    assert_eq!(b.reserve_process(0, 0).unwrap().maximum_duration, Duration::from_secs(1));
    let mut b = Budget::new(); b.test_elapsed = Some(Duration::ZERO);
    assert_eq!(b.reserve_process(0, 0).unwrap().maximum_duration, Duration::from_secs(2));
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
            self.0 += 1; Err(std::io::Error::other("injected read failure"))
        }
    }
    let mut b = Budget::new(); let mut fault = Fault(0); let mut buf = [0; 17];
    assert_eq!(read_chunk(&mut fault, &mut buf, &mut b).err(), Some(IncompleteReason::Io));
    assert_eq!(b.counters.observed_file_bytes, 0);
    assert_eq!(b.counters.uncertain_file_reservation_bytes, 17);
    assert_eq!(b.counters.charged_read_bytes, 17);
    assert!(read_chunk(&mut fault, &mut buf, &mut b).is_err());
    assert_eq!(fault.0, 1);
}

#[test]
fn census_rechecks_names_and_anchors() {
    struct Change { path: std::path::PathBuf, when: Event, done: bool }
    impl Boundary for Change {
        fn event(&mut self, e: Event, _: &[u8], _: Option<&Identity>) -> Result<(), IncompleteReason> {
            if e == self.when && !self.done {
                self.done = true;
                if e == Event::BeforeAnchorRecheck {
                    fs::rename(&self.path, self.path.with_extension("moved")).unwrap();
                    fs::create_dir(&self.path).unwrap();
                } else { fs::write(self.path.join("late"), b"late").unwrap(); }
            }
            Ok(())
        }
    }
    for when in [Event::BeforeReenumerate, Event::BeforeAnchorRecheck] {
        let f = InspectionFixture::directory(); f.write(b"a", b"abc");
        let mut hook = Change { path:f.checkout.clone(), when, done:false };
        assert_eq!(filesystem::walk(&f.checkout, &mut Budget::new(), &mut hook).err(), Some(IncompleteReason::Changed));
        assert!(hook.done);
    }
}

#[test]
fn outside_parent_sibling_churn_preserves_private_census() {
    struct Siblings { parent: std::path::PathBuf, fired: bool }
    impl Boundary for Siblings {
        fn event(&mut self, e: Event, _: &[u8], _: Option<&Identity>) -> Result<(), IncompleteReason> {
            if e == Event::BeforeAnchorRecheck && !self.fired {
                self.fired = true;
                fs::write(self.parent.join("outside-file"), b"unrelated").unwrap();
                fs::create_dir(self.parent.join("outside-directory")).unwrap();
            }
            Ok(())
        }
    }
    let f = InspectionFixture::directory(); f.write(b"a", b"abc");
    let mut h = Siblings { parent:f.temp.path().to_owned(), fired:false };
    let mut b = Budget::new();
    let census = filesystem::walk(&f.checkout, &mut b, &mut h).unwrap();
    assert!(h.fired);
    assert_eq!(census.entries.len(), 1);
    assert_eq!(census.entries[0].path.as_bytes(), b"a");
    let expected: [u8;32] = Sha256::digest(b"abc").into();
    assert_eq!(census.entries[0].content_sha256, Some(expected));
    assert_eq!(b.counters.observed_file_bytes, 3);
    assert_eq!(b.counters.child_launches, 0);
}

#[test]
fn outside_ancestor_binding_changes_still_refuse() {
    use std::os::unix::fs::PermissionsExt;
    struct Replace { ancestor: std::path::PathBuf, kind: &'static str, fired: bool }
    impl Boundary for Replace {
        fn event(&mut self, e: Event, _: &[u8], _: Option<&Identity>) -> Result<(), IncompleteReason> {
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
        let mut h = Replace { ancestor, kind, fired:false };
        assert_eq!(filesystem::walk(&checkout, &mut Budget::new(), &mut h).err(), Some(IncompleteReason::Changed), "{kind}");
        assert!(h.fired, "ancestor mutation was not reached: {kind}");
    }
}

#[test]
fn final_recheck_still_covers_root_and_descendant_contents() {
    struct Change { checkout: std::path::PathBuf, kind: &'static str, fired: bool }
    impl Boundary for Change {
        fn event(&mut self, e: Event, _: &[u8], _: Option<&Identity>) -> Result<(), IncompleteReason> {
            if e == Event::BeforeAnchorRecheck && !self.fired {
                self.fired = true;
                match self.kind {
                    "root" => fs::create_dir(self.checkout.join("late")).unwrap(),
                    "directory" => fs::create_dir(self.checkout.join("sub/late")).unwrap(),
                    "file" => fs::write(self.checkout.join("sub/a"), b"changed and longer").unwrap(),
                    _ => unreachable!(),
                }
            }
            Ok(())
        }
    }
    for kind in ["root", "directory", "file"] {
        let f = InspectionFixture::directory();
        fs::create_dir(f.path(b"sub")).unwrap(); f.write(b"sub/a", b"abc");
        let mut h = Change { checkout:f.checkout.clone(), kind, fired:false };
        assert_eq!(filesystem::walk(&f.checkout, &mut Budget::new(), &mut h).err(), Some(IncompleteReason::Changed), "{kind}");
        assert!(h.fired, "final mutation was not reached: {kind}");
    }
}

#[test]
fn raw_names_and_ignored_descendants_are_all_observed() {
    let f = InspectionFixture::linked(); let names = f.raw_payloads();
    let mut b = Budget::new();
    let census = filesystem::walk(&f.checkout, &mut b, &mut SystemBoundary).unwrap();
    for name in names {
        let found = census.entries.iter().find(|e| e.path.as_bytes() == name).unwrap();
        let expected: [u8; 32] = sha2::Sha256::digest(b"abc").into();
        assert_eq!(found.content_sha256, Some(expected));
    }
    assert!(census.entries.iter().any(|e| e.path.as_bytes() == b"cache/empty"));
    assert!(census.entries.iter().any(|e| e.path.as_bytes() == b".git")); // ordinary file, NOT administrative exemption
    assert!(census.entries.windows(2).all(|p| p[0].path < p[1].path));
    assert!(b.counters.directory_reserved_bytes >= (DIRECTORY_BUFFER_BYTES * 4) as u64);
    assert!(b.counters.observed_file_bytes > 0);
    assert_eq!(b.counters.charged_read_bytes, b.counters.observed_file_bytes + b.counters.directory_reserved_bytes);
    assert_eq!(b.counters.child_launches, 0); // Fixture Git is not inspection Git.
}

#[test]
fn stable_links_specials_and_nested_git_never_reach_data_open() {
    #[derive(Default)]
    struct Count { opens: usize, rejected: Option<(Vec<u8>, IncompleteReason)>, anchor_rejected: Option<(Vec<u8>, IncompleteReason)> }
    impl Boundary for Count {
        fn event(&mut self, e: Event, _: &[u8], _: Option<&Identity>) -> Result<(), IncompleteReason> {
            if e == Event::BeforeDataOpen { self.opens += 1; } Ok(())
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
            "hardlink" => { fs::write(f.temp.path().join("outside"), b"x").unwrap(); fs::hard_link(f.temp.path().join("outside"), f.path(b"a")).unwrap(); }
            "fifo" => rustix::fs::mknodat(rustix::fs::CWD, f.path(b"a"), rustix::fs::FileType::Fifo, rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR, 0).unwrap(),
            "socket" => socket = Some(std::os::unix::net::UnixListener::bind(f.path(b"a")).unwrap()),
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
        assert_eq!(filesystem::walk(&f.checkout, &mut Budget::new(), &mut h).err(), Some(reason), "{case}");
        assert_eq!(h.rejected, Some((path.to_vec(), reason)), "decision not reached: {case}");
        assert_eq!(h.opens, 0, "{case}"); drop(socket);
    }
    let f = InspectionFixture::directory();
    symlink(&f.checkout, f.temp.path().join("alias")).unwrap();
    let mut h = Count::default();
    let reason = filesystem::walk(&f.temp.path().join("alias"), &mut Budget::new(), &mut h).err().unwrap();
    // O_PATH|DIRECTORY|NOFOLLOW may report ENOTDIR, or resolution ELOOP.
    // Both must come from the actual alias component, not earlier proc/setup.
    assert!(matches!(reason, IncompleteReason::Changed | IncompleteReason::UnsupportedResolution));
    assert_eq!(h.anchor_rejected, Some((b"alias".to_vec(), reason)));
    assert_eq!(h.opens, 0);
}

#[test]
fn filesystem_only_empty_file_positive_and_main_git_refusal() {
    let f = InspectionFixture::directory(); f.write(b"empty", b"");
    let mut b = Budget::new();
    let census = filesystem::walk(&f.checkout, &mut b, &mut SystemBoundary).unwrap();
    let expected: [u8;32] = Sha256::digest(b"").into();
    assert_eq!(census.entries.len(), 1);
    assert_eq!(census.entries[0].content_sha256, Some(expected));
    assert_eq!(b.counters.observed_file_bytes, 0);
    assert_eq!(b.counters.uncertain_file_reservation_bytes, 0);
    assert_eq!(b.counters.charged_read_bytes, b.counters.directory_reserved_bytes);
    fs::create_dir(f.path(b".git")).unwrap();
    assert_eq!(filesystem::walk(&f.checkout, &mut Budget::new(), &mut SystemBoundary).err(), Some(IncompleteReason::GitMetadataUnproven));
}

#[test]
fn simulated_device_is_rejected_before_data_open() {
    // Injected fstat type only; this is not live-device/OS qualification.
    struct Device { opens: usize, fired: bool, rejected: bool }
    impl Boundary for Device {
        fn child_identity(&mut self, mut i: Identity) -> Identity { self.fired = true; i.mode = 0o020600; i }
        fn rejected(&mut self, path: &[u8], reason: IncompleteReason) {
            assert_eq!(path, b"a"); assert_eq!(reason, IncompleteReason::SpecialFile);
            self.rejected = true;
        }
        fn event(&mut self, e: Event, _: &[u8], _: Option<&Identity>) -> Result<(), IncompleteReason> {
            if e == Event::BeforeDataOpen { self.opens += 1; } Ok(())
        }
    }
    let f = InspectionFixture::directory(); f.write(b"a", b"abc");
    let mut h = Device { opens:0, fired:false, rejected:false };
    assert_eq!(filesystem::walk(&f.checkout, &mut Budget::new(), &mut h).err(), Some(IncompleteReason::SpecialFile));
    assert!(h.fired && h.rejected, "injected type/rejection was not reached");
    assert_eq!(h.opens, 0);
}

#[test]
fn growth_and_missing_names_invalidate_the_private_census() {
    struct Change { path: std::path::PathBuf, grow: bool, fired: bool }
    impl Boundary for Change {
        fn event(&mut self, e: Event, _: &[u8], _: Option<&Identity>) -> Result<(), IncompleteReason> {
            if e == Event::BeforeFileRead {
                self.fired = true;
                if self.grow { fs::write(&self.path, b"larger than before").unwrap(); }
                else { fs::remove_file(&self.path).unwrap(); }
            } Ok(())
        }
    }
    for grow in [true, false] {
        let f = InspectionFixture::directory(); f.write(b"a", b"abc");
        let mut h = Change { path:f.path(b"a"), grow, fired:false };
        assert_eq!(filesystem::walk(&f.checkout, &mut Budget::new(), &mut h).err(), Some(IncompleteReason::Changed));
        assert!(h.fired, "growth/unlink mutation was not reached");
    }
}
