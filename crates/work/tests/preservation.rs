//! SOURCE FIRST: run only in the owned-fixture GitHub job, never on the authoring host.
#[path = "support/inspection_fixture.rs"]
mod fixture;
use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Output, Stdio},
};
use work_cli as work_cli_api;

fn command(config: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_work"))
        .env_clear()
        .env("WORK_CONFIG", config)
        .args(args)
        .output()
        .unwrap()
}
fn configured(f: &fixture::ManagedFixture) -> std::path::PathBuf {
    let remote = f.temp.path().join("backup.git");
    fixture::git(
        f.temp.path(),
        &[
            "init".as_ref(),
            "--bare".as_ref(),
            "--template=".as_ref(),
            remote.as_os_str(),
        ],
    );
    let url = format!("file://{}", remote.display());
    f.git(&[
        "remote".as_ref(),
        "add".as_ref(),
        "backup".as_ref(),
        url.as_ref(),
    ]);
    f.git(&[
        "-c".as_ref(),
        "protocol.file.allow=always".as_ref(),
        "push".as_ref(),
        "backup".as_ref(),
        "HEAD:refs/heads/preserved".as_ref(),
    ]);
    let config = f.temp.path().join("config.toml");
    fs::write(&config, format!("store_dir={:?}\ntrusted_registry={:?}\nroots=[{:?}]\n[remote_preservation]\nformat=1\nversion='fixture-v1'\n[[remote_preservation.targets]]\ncommon_dir={:?}\nremote='backup'\nurl={url:?}\nbranch='refs/heads/preserved'\n[capture]\nexecutable=false\n", f.temp.path().join("authority"), f.temp.path().join("registry"), f.root, f.common())).unwrap();
    config
}
fn audit(f: &fixture::ManagedFixture, config: &Path) -> (Output, serde_json::Value) {
    let out = command(
        config,
        &["audit-preservation", &f.allocation.checkout.to_string()],
    );
    let report = serde_json::from_slice(&out.stdout).unwrap_or_else(|_| panic!("{out:?}"));
    (out, report)
}
// Small stdin/output adapter for native object creation; the existing fixture
// owns authority/worktrees. No synthetic positive OIDs or command responses.
fn object_git(f: &fixture::ManagedFixture, args: &[&str], input: &[u8]) -> String {
    let mut child = Command::new("/usr/bin/git")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args([
            "-c",
            "user.name=Owned Fixture",
            "-c",
            "user.email=fixture@invalid",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "pack.writeReverseIndex=false",
        ])
        .args(args)
        .current_dir(&f.allocation.destination)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "owned object creation failed");
    String::from_utf8(output.stdout)
        .unwrap()
        .trim_end()
        .to_owned()
}
fn holds(report: &serde_json::Value, reason: &str) -> bool {
    report["additional_work_holds"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["reason"] == reason)
}
fn root<'a>(report: &'a serde_json::Value, oid: &str) -> &'a serde_json::Value {
    report["recovery_manifest"]["roots"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["oid"] == oid)
        .unwrap()
}
fn provenance(report: &serde_json::Value, oid: &str, kind: &str) -> bool {
    root(report, oid)["provenance"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["kind"] == kind)
}
fn original(path: &Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    let mut out = vec![];
    for entry in fs::read_dir(path).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(original(&path));
        } else {
            out.push((path.clone(), fs::read(path).unwrap()));
        }
    }
    out.sort();
    out
}
#[test]
fn native_positive_is_passive_and_original_git_bytes_are_unchanged() {
    let f = fixture::ManagedFixture::new("sha1", "2");
    let config = configured(&f);
    let before = original(f.common());
    let authority_before: Vec<_> = ["store.sqlite", "store.sqlite-wal"]
        .into_iter()
        .map(|name| {
            let path = f.temp.path().join("authority").join(name);
            let bytes = fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect();
    let (out, report) = audit(&f, &config);
    assert!(out.status.success(), "{report}");
    for (path, bytes) in authority_before {
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
    assert_eq!(report["coverage"], "complete");
    assert_eq!(report["outcome"], "observed");
    assert_eq!(report["remote_head"]["outcome"], "observed");
    assert_eq!(report["remote_head"]["transport"], "LOCAL");
    assert_eq!(report["recorded"], false);
    assert_eq!(report["retirement_authority"], false);
    assert_eq!(report["cleanup"], "complete");
    assert_eq!(original(f.common()), before);
    assert!(!f.common().join("refs/work-recovery").exists());
    let (_, repeated) = audit(&f, &config);
    assert_eq!(report["recovery_manifest"], repeated["recovery_manifest"]);
    for r in report["recovery_manifest"]["roots"].as_array().unwrap() {
        assert_eq!(
            r["proposed_ref"],
            format!(
                "refs/work-recovery/{}/sha1/{}",
                f.allocation.checkout,
                r["oid"].as_str().unwrap()
            )
        );
    }
    assert_eq!(
        command(&config, &["audit-preservation", &report.to_string()])
            .status
            .code(),
        Some(2)
    );
    assert!(!f
        .temp
        .path()
        .join("authority/inspection-receipts-v1")
        .exists());
}
#[test]
fn head_covered_does_not_hide_another_branch_or_shared_ownership() {
    let f = fixture::ManagedFixture::new("sha1", "2");
    let config = configured(&f);
    let tree = object_git(&f, &["rev-parse", "HEAD^{tree}"], b"");
    let other = object_git(&f, &["commit-tree", &tree, "-m", "other work"], b"");
    f.git(&[
        "update-ref".as_ref(),
        "refs/heads/other".as_ref(),
        other.as_ref(),
    ]);
    let (out, report) = audit(&f, &config);
    assert_eq!(out.status.code(), Some(1), "{report}");
    assert_eq!(report["remote_head"]["outcome"], "observed");
    assert_eq!(
        root(&report, &other)["remote_relationship"],
        "not_reachable"
    );
    assert!(provenance(&report, &other, "named_ref"));
    assert!(holds(&report, "unpreserved_object"));
    assert!(holds(&report, "shared_work_ownership_unknown"));
}
#[test]
fn deleted_branch_reflog_old_and_new_endpoints_are_both_required() {
    let f = fixture::ManagedFixture::new("sha1", "2");
    let config = configured(&f);
    let head = object_git(&f, &["rev-parse", "HEAD"], b"");
    let tree = object_git(&f, &["rev-parse", "HEAD^{tree}"], b"");
    let old = object_git(&f, &["commit-tree", &tree, "-m", "deleted work"], b"");
    f.git(&[
        "update-ref".as_ref(),
        "refs/heads/deleted".as_ref(),
        old.as_ref(),
    ]);
    f.git(&[
        "update-ref".as_ref(),
        "-d".as_ref(),
        "refs/heads/deleted".as_ref(),
    ]);
    // The remaining HEAD log records a transition away from the deleted work.
    let log = f.private().join("logs/HEAD");
    let mut bytes = fs::read(&log).unwrap();
    bytes.extend(
        format!("{old} {head} Owned Fixture <fixture@invalid> 1 +0000\tDO_NOT_ECHO\n").bytes(),
    );
    fs::write(&log, bytes).unwrap();
    let (out, report) = audit(&f, &config);
    assert_eq!(out.status.code(), Some(1), "{report}");
    assert!(provenance(&report, &old, "reflog_old"));
    assert!(provenance(&report, &head, "reflog_new"));
    assert!(!report.to_string().contains("DO_NOT_ECHO"));
    assert!(!report.to_string().contains("fixture@invalid"));
}
#[test]
fn all_object_census_includes_packed_and_loose_unreachable_and_standalone_objects() {
    let f = fixture::ManagedFixture::new("sha1", "2");
    let config = configured(&f);
    let tree = object_git(&f, &["rev-parse", "HEAD^{tree}"], b"");
    let packed = object_git(&f, &["commit-tree", &tree, "-m", "packed unreachable"], b"");
    let prefix = f.common().join("objects/pack/pack");
    object_git(
        &f,
        &["pack-objects", prefix.to_str().unwrap()],
        format!("{packed}\n").as_bytes(),
    );
    fs::remove_file(
        f.common()
            .join("objects")
            .join(&packed[..2])
            .join(&packed[2..]),
    )
    .unwrap();
    let loose = object_git(&f, &["commit-tree", &tree, "-m", "loose unreachable"], b"");
    let blob = object_git(
        &f,
        &["hash-object", "-w", "--stdin"],
        b"unclassified payload",
    );
    let standalone_tree = object_git(
        &f,
        &["mktree"],
        format!("100644 blob {blob}\tstandalone\n").as_bytes(),
    );
    let tag = object_git(&f, &["mktag"], format!("object {blob}\ntype blob\ntag unattached\ntagger Owned Fixture <fixture@invalid> 1 +0000\n\nstandalone tag\n").as_bytes());
    let refs_only = object_git(
        &f,
        &["rev-list", "--objects", "--no-object-names", "--all"],
        b"",
    );
    assert!(!refs_only.contains(&packed));
    assert!(!refs_only.contains(&blob));
    let before = original(f.common());
    let (out, report) = audit(&f, &config);
    assert_eq!(out.status.code(), Some(1), "{report}");
    for id in [&packed, &loose] {
        assert!(provenance(&report, id, "unreachable_census"), "{report}");
    }
    for (id, kind) in [(&blob, "blob"), (&standalone_tree, "tree"), (&tag, "tag")] {
        assert_eq!(root(&report, id)["object_type"], kind);
        assert!(provenance(&report, id, "unclassified_census"));
    }
    assert!(holds(&report, "unclassified_local_work"));
    assert_eq!(original(f.common()), before);
}
#[test]
fn sibling_administration_pseudorefs_and_named_tags_are_not_excluded() {
    let f = fixture::ManagedFixture::new("sha1", "2");
    let config = configured(&f);
    let sibling = f.sibling();
    let gitfile = fs::read_to_string(sibling.join(".git")).unwrap();
    let admin = Path::new(gitfile.trim_end().strip_prefix("gitdir: ").unwrap());
    let tree = object_git(&f, &["rev-parse", "HEAD^{tree}"], b"");
    let other = object_git(&f, &["commit-tree", &tree, "-m", "sibling only"], b"");
    fs::write(admin.join("ORIG_HEAD"), format!("{other}\n")).unwrap();
    let log = admin.join("logs/HEAD");
    let mut bytes = fs::read(&log).unwrap();
    bytes.extend(
        format!(
            "{} {other} Owned Fixture <fixture@invalid> 1 +0000\tsibling\n",
            "0".repeat(40)
        )
        .bytes(),
    );
    fs::write(log, bytes).unwrap();
    f.git(&[
        "tag".as_ref(),
        "-a".as_ref(),
        "-m".as_ref(),
        "named tag".as_ref(),
        "local-tag".as_ref(),
        other.as_ref(),
    ]);
    let tag = object_git(&f, &["rev-parse", "refs/tags/local-tag"], b"");
    // Payload is intentionally unsafe to recurse into. Only admin inputs are in scope.
    std::os::unix::fs::symlink("/unavailable", sibling.join("payload-link")).unwrap();
    let (out, report) = audit(&f, &config);
    assert_eq!(out.status.code(), Some(1), "{report}");
    assert_eq!(report["coverage"], "complete", "{report}");
    assert!(provenance(&report, &other, "pseudoref"));
    assert!(provenance(&report, &other, "reflog_new"));
    assert!(provenance(&report, &tag, "named_ref"));
    assert_eq!(root(&report, &tag)["object_type"], "tag");
    assert!(holds(&report, "shared_work_ownership_unknown"));
}
#[test]
fn remote_graph_is_captured_before_local_import() {
    let f = fixture::ManagedFixture::new("sha1", "2");
    let config = configured(&f);
    fs::write(f.path(b"tracked"), b"local only graph\n").unwrap();
    f.git(&[
        "commit".as_ref(),
        "-am".as_ref(),
        "unpreserved HEAD".as_ref(),
    ]);
    let head = object_git(&f, &["rev-parse", "HEAD"], b"");
    let (out, report) = audit(&f, &config);
    assert_eq!(out.status.code(), Some(1), "{report}");
    assert_eq!(root(&report, &head)["remote_relationship"], "not_reachable");
    assert!(holds(&report, "unpreserved_object"));
    assert_eq!(report["remote_head"]["reason"], "nonancestor");
}
#[test]
fn dirty_findings_are_independent_of_preserved_head() {
    for (name, kind) in [
        (b"tracked".as_slice(), "tracked_content"),
        (b"new", "untracked"),
        (b"cache/unknown", "ignored_unclassified"),
    ] {
        let f = fixture::ManagedFixture::new("sha1", "2");
        let config = configured(&f);
        fs::create_dir_all(f.path(name).parent().unwrap()).unwrap();
        fs::write(f.path(name), b"not backed up\n").unwrap();
        let (out, report) = audit(&f, &config);
        assert_eq!(out.status.code(), Some(1), "{report}");
        assert_eq!(report["remote_head"]["outcome"], "observed");
        assert!(report["inspection_findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["kind"] == kind));
    }
}
#[test]
fn malformed_missing_and_unsupported_inputs_are_incomplete_without_repair() {
    for case in [
        "malformed-log",
        "missing-log-object",
        "missing-object",
        "missing-remote-object",
        "private-refs",
        "unknown-admin",
        "unsafe-config",
        "inspection-policy",
    ] {
        let f = fixture::ManagedFixture::new("sha1", "2");
        let config = configured(&f);
        match case {
            "malformed-log" => fs::write(f.private().join("logs/HEAD"), b"DO_NOT_ECHO\n").unwrap(),
            "missing-log-object" => fs::write(
                f.private().join("logs/HEAD"),
                format!(
                    "{} {} Owned Fixture <fixture@invalid> 1 +0000\tmessage\n",
                    "0".repeat(40),
                    "1".repeat(40)
                ),
            )
            .unwrap(),
            "missing-object" => {
                let head = object_git(&f, &["rev-parse", "HEAD"], b"");
                fs::remove_file(f.common().join("objects").join(&head[..2]).join(&head[2..]))
                    .unwrap();
            }
            "missing-remote-object" => {
                let head = object_git(&f, &["rev-parse", "HEAD"], b"");
                fs::remove_file(
                    f.temp
                        .path()
                        .join("backup.git/objects")
                        .join(&head[..2])
                        .join(&head[2..]),
                )
                .unwrap();
            }
            "private-refs" => {
                fs::create_dir_all(f.private().join("refs/worktree")).unwrap();
                fs::write(f.private().join("refs/worktree/hidden"), "1".repeat(40)).unwrap();
            }
            "unknown-admin" => fs::write(f.private().join("FUTURE_HEAD"), "1".repeat(40)).unwrap(),
            "unsafe-config" => f.git(&[
                "config".as_ref(),
                "core.fsmonitor".as_ref(),
                "DO_NOT_ECHO".as_ref(),
            ]),
            _ => {
                let text = fs::read_to_string(&config).unwrap();
                fs::write(&config, format!("{text}\n[inspection]\nformat=false\n")).unwrap();
            }
        }
        let before = original(f.common());
        let (out, report) = audit(&f, &config);
        assert_eq!(out.status.code(), Some(1), "{case}: {report}");
        assert_eq!(report["coverage"], "incomplete", "{case}: {report}");
        assert_eq!(original(f.common()), before);
        assert!(!report.to_string().contains("DO_NOT_ECHO"));
    }
}
#[test]
fn cli_help_uuid_policy_and_old_report_are_sanitized() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("absent.toml");
    let help = command(&config, &["audit-preservation", "--help"]);
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    for flag in ["--url", "--record", "--approve", "--delete"] {
        assert!(!help.contains(flag));
    }
    for args in [
        vec!["audit-preservation", "DO_NOT_ECHO"],
        vec!["audit-preservation", "--url", "DO_NOT_ECHO"],
        vec!["audit-preservation", "00000000-0000-0000-0000-000000000000"],
        vec!["audit-preservation", "{\"observed\":true}"],
    ] {
        let out = command(&config, &args);
        assert_eq!(out.status.code(), Some(2));
        assert!(!String::from_utf8_lossy(&out.stderr).contains("DO_NOT_ECHO"));
    }
    let out = command(
        &config,
        &["audit-preservation", &uuid::Uuid::now_v7().to_string()],
    );
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
}
#[test]
fn existing_recovery_ref_does_not_classify_or_clear_unclassified_holds() {
    let f = fixture::ManagedFixture::new("sha1", "2");
    let config = configured(&f);
    let blob = object_git(
        &f,
        &["hash-object", "-w", "--stdin"],
        b"unclassified payload",
    );
    let name = format!("refs/work-recovery/{}/sha1/{}", f.allocation.checkout, blob);
    f.git(&["update-ref".as_ref(), name.as_ref(), blob.as_ref()]);
    let (out, report) = audit(&f, &config);
    assert_eq!(out.status.code(), Some(1), "{report}");
    assert!(holds(&report, "unclassified_local_work"));
    assert!(provenance(&report, &blob, "unclassified_census"));
    assert!(!provenance(&report, &blob, "named_ref"));
}
