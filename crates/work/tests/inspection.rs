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
    let git_version = std::process::Command::new("/usr/bin/git")
        .arg("--version")
        .output()
        .unwrap();
    assert!(git_version.status.success());
    let git_version = String::from_utf8(git_version.stdout).unwrap();
    for (format, version) in [
        ("sha1", "2"),
        ("sha1", "3"),
        ("sha256", "2"),
        ("sha256", "3"),
    ] {
        let mut f = fixture::ManagedFixture::new(format, version);
        // Native files-backend creation leaves an ordinary empty private refs
        // directory. Keep it intact: admission must support this native layout.
        let private_refs = f.private().join("refs");
        assert!(fs::symlink_metadata(&private_refs).unwrap().is_dir());
        assert!(fs::read_dir(&private_refs).unwrap().next().is_none());
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
        assert_eq!(observation.git_version(), Some(git_version.trim_end()));
        assert_eq!(before, fs::read(f.private().join("index")).unwrap());
        assert_eq!(events, f.store.pending_events(100).unwrap());
        assert_eq!(f.store.charged(&f.repo, None).unwrap(), 1);
    }
}

#[test]
fn native_repack_metadata_is_readonly() {
    for format in ["sha1", "sha256"] {
        let mut f = fixture::ManagedFixture::new(format, "2");
        f.git(&[
            "-c".as_ref(),
            "pack.writeReverseIndex=true".as_ref(),
            "repack".as_ref(),
            "-ad".as_ref(),
        ]);
        // Native maintenance may leave this empty directory even with no graph.
        fs::create_dir_all(f.repo.join(".git/objects/info/commit-graphs")).unwrap();
        let pack_dir = f.repo.join(".git/objects/pack");
        let mut paths: Vec<_> = fs::read_dir(&pack_dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert!(paths
            .iter()
            .any(|p| p.extension().is_some_and(|e| e == "rev")));
        paths.push(f.repo.join(".git/objects/info/packs"));
        let before: Vec<_> = paths.iter().map(|p| fs::read(p).unwrap()).collect();
        let events = f.store.pending_events(100).unwrap();
        let observation = f.inspect(&empty());
        assert_eq!(
            observation.coverage(),
            Coverage::Complete,
            "{format}: {:?}",
            observation.reasons()
        );
        assert!(observation.findings().is_empty());
        for (path, bytes) in paths.iter().zip(before) {
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
        assert_eq!(f.store.pending_events(100).unwrap(), events);
    }
}

#[test]
fn native_commit_graphs_are_verified_without_mutation() {
    for format in ["sha1", "sha256"] {
        let mut f = fixture::ManagedFixture::new(format, "2");
        // Exercise one standalone graph and a genuine two-layer split chain.
        for split in [false, true] {
            if split {
                fs::remove_file(f.common().join("objects/info/commit-graph")).unwrap();
            }
            let mut args = vec![
                "commit-graph".as_ref(),
                "write".as_ref(),
                "--reachable".as_ref(),
            ];
            if split {
                args.push("--split=no-merge".as_ref());
            }
            f.git(&args);
            f.git(&[
                "commit".as_ref(),
                "--allow-empty".as_ref(),
                "-m".as_ref(),
                "second".as_ref(),
            ]);
            f.git(&args);
            let info = f.common().join("objects/info");
            let paths: Vec<_> = if split {
                fs::read_dir(info.join("commit-graphs"))
                    .unwrap()
                    .map(|e| e.unwrap().path())
                    .collect()
            } else {
                vec![info.join("commit-graph")]
            };
            if split {
                assert_eq!(paths.len(), 3);
            }
            let before: Vec<_> = paths.iter().map(|p| fs::read(p).unwrap()).collect();
            let observation = f.inspect(&empty());
            assert_eq!(
                observation.coverage(),
                Coverage::Complete,
                "{format}/split={split}: {:?}",
                observation.reasons()
            );
            for (path, bytes) in paths.iter().zip(before) {
                assert_eq!(fs::read(path).unwrap(), bytes);
            }
        }
    }
}

#[test]
fn commit_graph_corruption_and_semantic_mismatches_hold() {
    for format in ["sha1", "sha256"] {
        let mut f = fixture::ManagedFixture::new(format, "2");
        f.git(&[
            "commit-graph".as_ref(),
            "write".as_ref(),
            "--reachable".as_ref(),
        ]);
        let path = f.common().join("objects/info/commit-graph");
        let bytes = fs::read(&path).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let width = if format == "sha1" { 20 } else { 32 };
        let data = (0..bytes[6] as usize)
            .find_map(|i| {
                let at = 8 + i * 12;
                (&bytes[at..at + 4] == b"CDAT").then(|| {
                    u64::from_be_bytes(bytes[at + 4..at + 12].try_into().unwrap()) as usize
                })
            })
            .unwrap();
        for case in [
            "checksum",
            "offset",
            "duplicate-chunk",
            "hash",
            "parent",
            "tree",
        ] {
            let mut bad = bytes.clone();
            match case {
                "checksum" => bad[0] ^= 1,
                "offset" => bad[12..20].copy_from_slice(&u64::MAX.to_be_bytes()),
                "duplicate-chunk" => {
                    let id = bad[8..12].to_vec();
                    bad[20..24].copy_from_slice(&id);
                }
                "hash" => bad[5] = 0,
                "parent" => bad[data + width..data + width + 4]
                    .copy_from_slice(&0xffff_ffffu32.to_be_bytes()),
                // Keep the envelope valid, but disagree with the actual commit.
                "tree" => bad[data] ^= 1,
                _ => unreachable!(),
            }
            if case != "checksum" {
                let file = f.temp.path().join("checksum-input");
                fs::write(&file, &bad[..bad.len() - width]).unwrap();
                let hash = if format == "sha1" {
                    let output = std::process::Command::new("/usr/bin/sha1sum")
                        .arg(&file)
                        .output()
                        .unwrap();
                    assert!(output.status.success());
                    String::from_utf8(output.stdout).unwrap()[..40].to_string()
                } else {
                    let output = std::process::Command::new("/usr/bin/sha256sum")
                        .arg(&file)
                        .output()
                        .unwrap();
                    assert!(output.status.success());
                    String::from_utf8(output.stdout).unwrap()[..64].to_string()
                };
                let digest: Vec<_> = (0..hash.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hash[i..i + 2], 16).unwrap())
                    .collect();
                let end = bad.len() - width;
                bad[end..].copy_from_slice(&digest);
            }
            fs::write(&path, &bad).unwrap();
            let observation = f.inspect(&empty());
            assert_eq!(
                observation.coverage(),
                Coverage::Incomplete,
                "{format}/{case}"
            );
            if case == "tree" {
                assert!(observation.counters().repository_launches > 0);
            } else {
                assert_eq!(
                    observation.counters().repository_launches,
                    0,
                    "{format}/{case}"
                );
            }
            assert_eq!(fs::read(&path).unwrap(), bad);
        }
        fs::write(&path, &bytes).unwrap();
        assert_eq!(f.inspect(&empty()).coverage(), Coverage::Complete);
    }
}

#[test]
fn auxiliary_pack_metadata_refuses_unsafe_or_unknown_inputs() {
    let mut f = fixture::ManagedFixture::new("sha1", "2");
    f.git(&[
        "-c".as_ref(),
        "pack.writeReverseIndex=true".as_ref(),
        "repack".as_ref(),
        "-ad".as_ref(),
    ]);
    let pack = f.common().join("objects/pack");
    let reverse = fs::read_dir(&pack)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "rev"))
        .unwrap();
    let info = f.common().join("objects/info/packs");
    let graphs = f.common().join("objects/info/commit-graphs");
    let rev_bytes = fs::read(&reverse).unwrap();
    let info_bytes = fs::read(&info).unwrap();
    let sentinel = f.temp.path().join("sentinel");
    fs::write(&sentinel, b"do not read as metadata").unwrap();
    for case in [
        "rev-link",
        "rev-hardlink",
        "rev-fifo",
        "info-link",
        "info-stale",
        "graphs-link",
        "graphs-nonempty",
        "orphan",
        "unknown",
    ] {
        let extra = pack.join(if case == "orphan" {
            format!("pack-{}.rev", "1".repeat(40))
        } else {
            "foreign.bitmap".into()
        });
        match case {
            "rev-link" => {
                fs::remove_file(&reverse).unwrap();
                symlink(&sentinel, &reverse).unwrap();
            }
            "rev-hardlink" => {
                fs::remove_file(&reverse).unwrap();
                fs::hard_link(&sentinel, &reverse).unwrap();
            }
            "rev-fifo" => {
                fs::remove_file(&reverse).unwrap();
                rustix::fs::mknodat(
                    rustix::fs::CWD,
                    &reverse,
                    rustix::fs::FileType::Fifo,
                    rustix::fs::Mode::RUSR,
                    0,
                )
                .unwrap();
            }
            "info-link" => {
                fs::remove_file(&info).unwrap();
                symlink(&sentinel, &info).unwrap();
            }
            "info-stale" => {
                fs::write(&info, format!("P pack-{}.pack\n\n", "1".repeat(40))).unwrap()
            }
            "graphs-link" => symlink(&sentinel, &graphs).unwrap(),
            "graphs-nonempty" => {
                fs::create_dir(&graphs).unwrap();
                fs::write(graphs.join("commit-graph-chain"), b"unsupported graph").unwrap();
            }
            "orphan" | "unknown" => fs::write(&extra, b"unrecognized").unwrap(),
            _ => unreachable!(),
        }
        let observation = f.inspect(&empty());
        assert_eq!(observation.coverage(), Coverage::Incomplete, "{case}");
        assert_eq!(observation.counters().repository_launches, 0, "{case}");
        assert_eq!(fs::read(&sentinel).unwrap(), b"do not read as metadata");
        if case.starts_with("rev-") {
            fs::remove_file(&reverse).unwrap();
            fs::write(&reverse, &rev_bytes).unwrap();
        }
        if case.starts_with("info-") {
            fs::remove_file(&info).unwrap();
            fs::write(&info, &info_bytes).unwrap();
        }
        if case == "orphan" || case == "unknown" {
            fs::remove_file(&extra).unwrap();
        }
        if case == "graphs-link" {
            fs::remove_file(&graphs).unwrap();
        }
        if case == "graphs-nonempty" {
            fs::remove_file(graphs.join("commit-graph-chain")).unwrap();
            fs::remove_dir(&graphs).unwrap();
        }
    }
    assert_eq!(f.inspect(&empty()).coverage(), Coverage::Complete);
}

#[test]
fn modest_tracked_payload_fits_read_budget_without_hiding_changes() {
    let mut f = fixture::ManagedFixture::new("sha1", "2");
    // Four MiB reproduces the real host checkout's failure with one file,
    // well below the unchanged 16 MiB file and 128 MiB invocation limits.
    let path = f.path(b"payload");
    let mut bytes = vec![b'a'; 4 * 1024 * 1024];
    fs::write(&path, &bytes).unwrap();
    f.git(&["add".as_ref(), "payload".as_ref()]);
    f.git(&["commit".as_ref(), "-m".as_ref(), "tracked payload".as_ref()]);
    let observation = f.inspect(&empty());
    assert_eq!(
        observation.coverage(),
        Coverage::Complete,
        "{:?}; {:?}",
        observation.reasons(),
        observation.counters()
    );
    assert!(observation.findings().is_empty());
    assert!(observation.counters().charged_read_bytes <= 128 * 1024 * 1024);
    bytes[0] = b'b';
    fs::write(&path, &bytes).unwrap();
    let changed = f.inspect(&empty());
    assert_eq!(
        changed.coverage(),
        Coverage::Complete,
        "{:?}",
        changed.reasons()
    );
    assert!(changed
        .findings()
        .iter()
        .any(|finding| finding.path().as_bytes() == b"payload"));
    assert_eq!(fs::read(&path).unwrap(), bytes);
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
fn ignore_lookup_treats_magic_and_wildcard_filenames_as_literal_paths() {
    let mut f = fixture::ManagedFixture::new("sha1", "2");
    fs::write(f.path(b".gitignore"), b"cache/\n:(literal)cache/\n").unwrap();
    let names = [
        b":(".as_slice(),
        b":(glob)tracked",
        b":(exclude)tracked",
        b"track?d",
        b"*",
        b"[t]racked",
        b"[",
    ];
    let scopes = [b"".as_slice(), b"cache", b":(literal)cache"];
    let mut expected = Vec::new();
    for scope in scopes {
        if !scope.is_empty() {
            fs::create_dir(f.path(scope)).unwrap();
            expected.push((scope.to_vec(), FindingKind::IgnoredUnclassified));
        }
        for name in names {
            let mut path = scope.to_vec();
            if !path.is_empty() {
                path.push(b'/');
            }
            path.extend_from_slice(name);
            fs::write(f.path(&path), b"literal payload\n").unwrap();
            expected.push((
                path,
                if scope.is_empty() {
                    FindingKind::Untracked
                } else {
                    FindingKind::IgnoredUnclassified
                },
            ));
        }
    }
    let before = fs::read(f.private().join("index")).unwrap();
    let o = f.inspect(&empty());
    assert_eq!(
        o.coverage(),
        Coverage::Complete,
        "reasons={:?}, counters={:?}",
        o.reasons(),
        o.counters()
    );
    for (path, kind) in expected {
        let entry = o
            .entries()
            .iter()
            .find(|e| e.path().as_bytes() == path)
            .unwrap();
        assert!(!entry.tracked());
        assert!(entry.policy_match().is_none());
        assert!(o
            .findings()
            .iter()
            .any(|finding| finding.path().as_bytes() == path && finding.kind() == kind));
    }
    // Names such as '*' and 'track?d' must not select the real tracked file.
    assert!(o
        .entries()
        .iter()
        .any(|e| e.path().as_bytes() == b"tracked" && e.tracked()));
    assert!(!o
        .findings()
        .iter()
        .any(|finding| finding.path().as_bytes() == b"tracked"));
    assert_eq!(before, fs::read(f.private().join("index")).unwrap());
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
fn private_refs_reject_links_special_files_and_nonempty_directories_before_git() {
    for case in [
        "symlink",
        "fifo",
        "regular-file",
        "direct-ref",
        "bisect",
        "worktree",
        "rewritten",
    ] {
        let mut f = fixture::ManagedFixture::new("sha1", "2");
        let refs = f.private().join("refs");
        assert!(fs::symlink_metadata(&refs).unwrap().is_dir());
        assert!(fs::read_dir(&refs).unwrap().next().is_none());
        match case {
            "symlink" => {
                let outside = f.temp.path().join("outside-empty-refs");
                fs::create_dir(&outside).unwrap();
                fs::remove_dir(&refs).unwrap();
                symlink(&outside, &refs).unwrap();
            }
            "fifo" => {
                fs::remove_dir(&refs).unwrap();
                rustix::fs::mknodat(
                    rustix::fs::CWD,
                    &refs,
                    rustix::fs::FileType::Fifo,
                    rustix::fs::Mode::RUSR,
                    0,
                )
                .unwrap();
            }
            "regular-file" => {
                fs::remove_dir(&refs).unwrap();
                fs::write(&refs, b"").unwrap();
            }
            "direct-ref" => {
                fs::write(refs.join("unexpected"), b"unsupported private ref\n").unwrap();
            }
            _ => fs::create_dir(refs.join(case)).unwrap(),
        }
        let o = f.inspect(&empty());
        assert_eq!(o.coverage(), Coverage::Incomplete, "{case}");
        assert_eq!(o.counters().child_launches, 0, "{case}");
        assert_eq!(o.counters().repository_launches, 0, "{case}");
        assert_eq!(o.counters().observed_process_bytes, 0, "{case}");
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
