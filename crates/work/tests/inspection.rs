//! Native fixtures are SOURCE ONLY until isolated CI. No synthetic completeness authority.
#[path = "support/inspection_fixture.rs"]
mod fixture;
use std::{
    fs,
    os::unix::{ffi::OsStrExt, fs::symlink},
};
use work_cli as work_cli_api;
use work_cli::{
    disposal::{validate, PolicyDocument, RawPath},
    inspection::{self, Coverage, FindingKind, IncompleteReason},
    store::Store,
};
fn empty() -> work_cli::disposal::ValidatedPolicies {
    validate(PolicyDocument {
        format: 1,
        policies: vec![],
    })
    .unwrap()
}

#[test]
fn native_sha1_sha256_v2_v3_positive() {
    for (format, version) in [
        ("sha1", "2"),
        ("sha1", "3"),
        ("sha256", "2"),
        ("sha256", "3"),
    ] {
        let mut f = fixture::ManagedFixture::new(format, version);
        let before = fs::read(f.private().join("index")).unwrap();
        assert_eq!(
            &before[4..8],
            &version.parse::<u32>().unwrap().to_be_bytes()
        );
        let events = f.store.pending_events(100).unwrap();
        let observation = f.inspect(&empty());
        assert_eq!(
            observation.coverage(),
            Coverage::Complete,
            "{format}/{version}: {:?}",
            observation.reasons()
        );
        assert!(observation.findings().is_empty());
        assert_eq!(observation.git_version(), Some("git version 2.55.0"));
        assert_eq!(before, fs::read(f.private().join("index")).unwrap());
        assert_eq!(events, f.store.pending_events(100).unwrap());
        assert_eq!(f.store.charged(&f.repo, None).unwrap(), 1);
    }
}

#[test]
fn raw_names_and_ignored_descendants_are_all_observed() {
    let mut f = fixture::ManagedFixture::new("sha1", "2");
    fs::create_dir_all(f.path(b"cache/empty")).unwrap();
    let names = [
        b"cache/\xff\n\t".as_slice(),
        b"cache/secret",
        b"cache/marker",
        b"arbitrary.pyc",
        b"-leading",
    ];
    for name in names {
        fs::write(f.path(name), b"abc").unwrap();
    }
    let payload = b"secret-payload-not-permitted-in-inspection-observations";
    fs::write(f.path(b"cache/secret"), payload).unwrap();
    let observation = f.inspect(&empty());
    assert_eq!(
        observation.coverage(),
        Coverage::Complete,
        "{:?}",
        observation.reasons()
    );
    for name in names {
        assert!(observation
            .entries()
            .iter()
            .any(|e| e.path().as_bytes() == name));
        assert!(observation
            .findings()
            .iter()
            .any(|e| e.path().as_bytes() == name));
    }
    assert!(observation
        .entries()
        .iter()
        .any(|e| e.path().as_bytes() == b"cache/empty"));
    assert!(observation.counters().child_launches > 0);
    assert!(observation.counters().observed_file_bytes > 0);
    assert!(!observation
        .canonical_bytes()
        .windows(payload.len())
        .any(|s| s == payload));
    let path = RawPath::from_bytes(names[0]).unwrap();
    assert_eq!(RawPath::from_hex(&path.to_hex()).unwrap(), path);
}

#[test]
fn hidden_index_flags_do_not_hide_changed_bytes() {
    for flag in ["--assume-unchanged", "--skip-worktree"] {
        let mut f = fixture::ManagedFixture::new("sha1", "3");
        f.git(&["update-index".as_ref(), flag.as_ref(), "tracked".as_ref()]);
        fs::write(f.path(b"tracked"), b"different\n").unwrap();
        let before = fs::read(f.private().join("index")).unwrap();
        let o = f.inspect(&empty());
        assert_eq!(
            o.coverage(),
            Coverage::Complete,
            "{flag}: {:?}",
            o.reasons()
        );
        assert!(o
            .findings()
            .iter()
            .any(|v| v.kind() == FindingKind::TrackedContent));
        let entry = o
            .entries()
            .iter()
            .find(|e| e.path().as_bytes() == b"tracked")
            .unwrap();
        assert!(entry.tracked());
        assert!(if flag == "--assume-unchanged" {
            entry.assume_unchanged()
        } else {
            entry.skip_worktree()
        });
        assert_eq!(before, fs::read(f.private().join("index")).unwrap());
    }
}
#[test]
fn inspection_does_not_write_index() {
    let mut f = fixture::ManagedFixture::new("sha1", "2");
    fs::write(f.path(b"tracked"), b"staged\0binary\n").unwrap();
    f.git(&["add".as_ref(), "tracked".as_ref()]);
    let before = fs::read(f.private().join("index")).unwrap();
    let o = f.inspect(&empty());
    assert_eq!(o.coverage(), Coverage::Complete, "{:?}", o.reasons());
    assert!(o
        .findings()
        .iter()
        .any(|v| v.kind() == FindingKind::StagedChange));
    assert_eq!(before, fs::read(f.private().join("index")).unwrap());
}

#[test]
fn native_git_input_preflight_and_manifest() {
    for case in [
        "loose-link",
        "ref-fifo",
        "config-link",
        "attribute",
        "include",
        "index4",
    ] {
        let mut f = fixture::ManagedFixture::new("sha1", "2");
        let sentinel = f.temp.path().join("sentinel");
        fs::write(&sentinel, b"outside metadata").unwrap();
        match case {
            "loose-link" => {
                let dir = f.common().join("objects/00");
                fs::create_dir_all(&dir).unwrap();
                symlink(&sentinel, dir.join("0".repeat(38))).unwrap();
            }
            "ref-fifo" => {
                rustix::fs::mknodat(
                    rustix::fs::CWD,
                    f.common().join("refs/heads/fifo"),
                    rustix::fs::FileType::Fifo,
                    rustix::fs::Mode::RUSR,
                    0,
                )
                .unwrap();
            }
            "config-link" => {
                fs::remove_file(f.common().join("config")).unwrap();
                symlink(&sentinel, f.common().join("config")).unwrap();
            }
            "attribute" => fs::write(f.path(b".gitattributes"), b"* filter=evil\n").unwrap(),
            "include" => {
                use std::io::Write;
                fs::OpenOptions::new()
                    .append(true)
                    .open(f.common().join("config"))
                    .unwrap()
                    .write_all(b"\n[include]\npath=/unconsulted/secret\n")
                    .unwrap();
            }
            "index4" => f.git(&["update-index".as_ref(), "--index-version=4".as_ref()]),
            _ => unreachable!(),
        }
        let o = f.inspect(&empty());
        assert_eq!(o.coverage(), Coverage::Incomplete, "{case}");
        // Version/config-stdin commands do not consult repo paths. All repository
        // commands remain behind the complete native-input admission boundary.
        assert_eq!(o.counters().repository_launches, 0, "{case}");
        assert_eq!(fs::read(&sentinel).unwrap(), b"outside metadata");
    }
}

#[test]
fn native_sibling_registration_locked_prunable_and_unconsulted_files() {
    for case in [
        "ordinary",
        "locked",
        "prunable",
        "invalid-head",
        "empty-gitdir",
    ] {
        let mut f = fixture::ManagedFixture::new("sha1", "2");
        let sibling = f.sibling();
        let private = f.common().join("worktrees/sibling");
        // An unknown sibling metadata symlink must not be opened or traversed.
        symlink("/unconsulted/sentinel", private.join("unknown")).unwrap();
        match case {
            "locked" => {
                fs::write(private.join("locked"), b"fixture lock\n").unwrap();
                fs::rename(&sibling, sibling.with_extension("gone")).unwrap();
            }
            "prunable" => fs::rename(&sibling, sibling.with_extension("gone")).unwrap(),
            "invalid-head" => fs::write(private.join("HEAD"), b"ref: refs/heads/absent\n").unwrap(),
            "empty-gitdir" => fs::write(private.join("gitdir"), b"").unwrap(),
            _ => (),
        }
        let o = f.inspect(&empty());
        assert_eq!(
            o.coverage(),
            if matches!(case, "invalid-head" | "empty-gitdir") {
                Coverage::Incomplete
            } else {
                Coverage::Complete
            },
            "{case}: {:?}",
            o.reasons()
        );
    }
}

#[test]
fn validation_cannot_restore_fresh_inspection_evidence() {
    let f = fixture::InspectionFixture::directory();
    let mut store = Store::open(
        &f.temp.path().join("authority"),
        std::slice::from_ref(&f.checkout),
    )
    .unwrap();
    let o = inspection::inspect(&mut store, uuid::Uuid::now_v7(), &empty()).unwrap();
    assert_eq!(o.coverage(), Coverage::Incomplete);
    assert!(o.reasons().contains(&IncompleteReason::ContextUnavailable));
    assert_eq!(o.counters().child_launches, 0);
    assert_eq!(o.counters().observed_file_bytes, 0);
}

#[test]
fn unsupported_native_features_refuse_without_filters_or_fetching() {
    for case in [
        "split-index",
        "gitlink",
        "tracked-attributes",
        "alternates",
        "promisor",
        "filter",
        "missing-object",
        "bad-backlink",
    ] {
        let mut f = fixture::ManagedFixture::new("sha1", "2");
        let marker = f.temp.path().join("must-not-execute");
        match case {
            "split-index" => f.git(&["update-index".as_ref(), "--split-index".as_ref()]),
            "gitlink" => {
                let value = format!("160000,{},nested", f.allocation.base_commit);
                f.git(&[
                    "update-index".as_ref(),
                    "--add".as_ref(),
                    "--cacheinfo".as_ref(),
                    value.as_ref(),
                ]);
            }
            "tracked-attributes" => {
                fs::write(f.path(b".gitattributes"), b"* text\n").unwrap();
                f.git(&["add".as_ref(), ".gitattributes".as_ref()]);
                fs::remove_file(f.path(b".gitattributes")).unwrap();
            }
            "alternates" => fs::write(
                f.common().join("objects/info/alternates"),
                b"/never-consulted\n",
            )
            .unwrap(),
            "promisor" => f.git(&[
                "config".as_ref(),
                "remote.origin.promisor".as_ref(),
                "true".as_ref(),
            ]),
            "filter" => {
                let command = format!("touch {}", marker.display());
                f.git(&[
                    "config".as_ref(),
                    "filter.bad.process".as_ref(),
                    command.as_ref(),
                ]);
            }
            "missing-object" => {
                let id = &f.allocation.base_commit;
                fs::remove_file(f.common().join("objects").join(&id[..2]).join(&id[2..])).unwrap();
            }
            "bad-backlink" => {
                fs::write(f.private().join("gitdir"), b"/never-consulted/.git\n").unwrap()
            }
            _ => unreachable!(),
        }
        let o = f.inspect(&empty());
        assert_eq!(o.coverage(), Coverage::Incomplete, "{case}");
        if case != "missing-object" {
            assert_eq!(o.counters().repository_launches, 0, "{case}");
        }
        assert!(!marker.exists(), "filter must not run");
    }
}

#[test]
fn non_utf8_tracked_path_uses_raw_protocols() {
    let mut f = fixture::ManagedFixture::new("sha1", "2");
    let raw = b"-tracked\xff\n\t";
    fs::write(f.path(raw), b"binary\0\n").unwrap();
    f.git(&[
        "add".as_ref(),
        "--".as_ref(),
        std::ffi::OsStr::from_bytes(raw),
    ]);
    let o = f.inspect(&empty());
    assert_eq!(o.coverage(), Coverage::Complete, "{:?}", o.reasons());
    assert!(o
        .findings()
        .iter()
        .any(|v| v.path().as_bytes() == raw && v.kind() == FindingKind::StagedChange));
}
