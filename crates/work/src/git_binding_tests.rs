//! Controlled fake-Git services, not supported-Git matrix qualification.
use super::*;
use std::ffi::OsStr;
use std::os::unix::{
    ffi::OsStrExt,
    fs::{symlink, PermissionsExt},
};

struct FakeGit {
    root: tempfile::TempDir,
    program: PathBuf,
    helpers: PathBuf,
}

impl FakeGit {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let program = root.path().join("git");
        let helpers = root.path().join("helpers");
        fs::create_dir(&helpers).unwrap();
        for name in REQUIRED_HELPERS {
            fs::write(helpers.join(name), b"#!/bin/sh\nexit 0\n").unwrap();
            fs::set_permissions(helpers.join(name), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let fixture = Self {
            root,
            program,
            helpers,
        };
        fixture.script("git version 2.55.0", "");
        fixture
    }

    fn script(&self, version: &str, extra: &str) {
        fs::write(&self.program, format!("#!/bin/sh\n{extra}\ncase \"$1\" in\n--version) printf '%s\\n' '{version}';;\n--exec-path) printf '%s\\n' '{}';;\n*) printf 'dispatch';;\nesac\n", self.helpers.display())).unwrap();
        fs::set_permissions(&self.program, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn candidate(&self, source: GitSelectionSource) -> GitCandidate {
        GitCandidate {
            path: self.program.clone(),
            source,
        }
    }
}

// Qualification runs in a fake-owner container. This controlled proof service
// is used only for fixture-created paths/ancestors and models mode protection,
// not production ownership/ACL proof. Real Linux access proof has separate tests;
// Darwin must be Unproven.
#[derive(Debug)]
struct FixtureAccess;
impl GitAccessProof for FixtureAccess {
    fn prove(&self, path: &Path, metadata: &fs::Metadata) -> Result<(), GitBindingError> {
        if !metadata.file_type().is_symlink()
            && metadata.mode() & 0o022 != 0
            && !(metadata.is_dir() && metadata.mode() & 0o1000 != 0)
        {
            return Err(error(path, GitBindingReason::UnsafeAccess));
        }
        Ok(())
    }
}
const ACCESS: FixtureAccess = FixtureAccess;

fn bind(f: &FakeGit) -> GitSelection<'static> {
    qualify_candidates(&[f.candidate(GitSelectionSource::Cli)], &ACCESS).unwrap()
}

#[test]
fn fake_git_binding_retains_original_canonical_version_helpers_and_profile() {
    let f = FakeGit::new();
    let alias = f.root.path().join("alias");
    symlink(&f.program, &alias).unwrap();
    let selection = qualify_candidates(
        &[GitCandidate {
            path: alias.clone(),
            source: GitSelectionSource::Config,
        }],
        &ACCESS,
    )
    .unwrap();
    let binding = &selection.binding;
    assert_eq!(
        binding.candidate.path.as_os_str().as_bytes(),
        alias.as_os_str().as_bytes()
    );
    assert_eq!(binding.canonical_program, f.program);
    assert_eq!(binding.helper_directory, f.helpers);
    assert_eq!(
        binding.version,
        GitVersion {
            major: 2,
            minor: 55,
            patch: 0
        }
    );
    let prepared = binding
        .command(["status"], |cmd| {
            cmd.env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("GIT_NO_REPLACE_OBJECTS", "1")
                .arg("--no-optional-locks");
        })
        .unwrap();
    assert_eq!(prepared.command.get_program(), f.program.as_os_str());
    let env: Vec<_> = prepared.command.get_envs().collect();
    assert!(env.contains(&(OsStr::new("GIT_EXEC_PATH"), Some(f.helpers.as_os_str()))));
    assert!(env.contains(&(OsStr::new("GIT_NO_REPLACE_OBJECTS"), Some(OsStr::new("1")))));
    assert!(env.contains(&(OsStr::new("PATH"), Some(OsStr::new("/usr/bin:/bin")))));
}

#[test]
fn fake_git_unsafe_nonregular_nonexec_refused_before_execution() {
    for kind in ["writable", "nonexec", "directory", "fifo", "parent"] {
        let f = FakeGit::new();
        let marker = f.root.path().join("executed");
        f.script(
            "git version 2.55.0",
            &format!("touch '{}'", marker.display()),
        );
        match kind {
            "writable" => {
                fs::set_permissions(&f.program, fs::Permissions::from_mode(0o777)).unwrap()
            }
            "nonexec" => {
                fs::set_permissions(&f.program, fs::Permissions::from_mode(0o600)).unwrap()
            }
            "directory" => {
                fs::remove_file(&f.program).unwrap();
                fs::create_dir(&f.program).unwrap();
            }
            "fifo" => {
                fs::remove_file(&f.program).unwrap();
                rustix::fs::mknodat(
                    rustix::fs::CWD,
                    &f.program,
                    rustix::fs::FileType::Fifo,
                    rustix::fs::Mode::RUSR,
                    0,
                )
                .unwrap();
            }
            "parent" => {
                fs::set_permissions(f.root.path(), fs::Permissions::from_mode(0o777)).unwrap()
            }
            _ => unreachable!(),
        }
        assert!(
            qualify_candidates(&[f.candidate(GitSelectionSource::Cli)], &ACCESS).is_err(),
            "{kind}"
        );
        assert!(!marker.exists(), "{kind} executed before validation");
    }
}

#[test]
fn fake_git_explicit_refusal_never_falls_back_but_defaults_advance() {
    for rejection in ["old", "vendor", "missing", "layout", "nonzero"] {
        let bad = FakeGit::new();
        let good = FakeGit::new();
        match rejection {
            "old" => bad.script("git version 2.54.0", ""),
            "vendor" => bad.script("git version 2.55.0.vendor", ""),
            "missing" => fs::remove_file(&bad.program).unwrap(),
            "layout" => fs::remove_file(bad.helpers.join(REQUIRED_HELPERS[0])).unwrap(),
            "nonzero" => bad.script("git version 2.55.0", "exit 1"),
            _ => unreachable!(),
        }
        let defaults = [
            bad.candidate(GitSelectionSource::PlatformDefault),
            good.candidate(GitSelectionSource::PlatformDefault),
        ];
        let selected = qualify_candidates(&defaults, &ACCESS).unwrap();
        assert_eq!(selected.binding.canonical_program, good.program);
        assert_eq!(selected.rejections.len(), 1);
        let explicit = [
            bad.candidate(GitSelectionSource::Cli),
            good.candidate(GitSelectionSource::PlatformDefault),
        ];
        assert_eq!(
            qualify_candidates(&explicit, &ACCESS)
                .unwrap_err()
                .rejections
                .len(),
            1
        );
    }
}

#[test]
fn fake_git_exec_path_protocol_and_helpers_are_required() {
    for output in [
        b"relative\n".as_slice(),
        b"/tmp\nextra\n",
        b"/tmp\0\n",
        b"/tmp",
        b"\n",
        b"/tmp\r\n",
    ] {
        let f = FakeGit::new();
        let bytes: String = output.iter().map(|b| format!("\\{:03o}", b)).collect();
        fs::write(&f.program, format!("#!/bin/sh\ncase \"$1\" in --version) echo 'git version 2.55.0';; *) printf '{bytes}';; esac\n")).unwrap();
        assert!(
            qualify_candidates(&[f.candidate(GitSelectionSource::Cli)], &ACCESS).is_err(),
            "{output:?}"
        );
    }
    for kind in ["missing", "writable", "nonexec", "helperdir"] {
        let f = FakeGit::new();
        let helper = f.helpers.join(REQUIRED_HELPERS[0]);
        match kind {
            "missing" => fs::remove_file(helper).unwrap(),
            "writable" => fs::set_permissions(helper, fs::Permissions::from_mode(0o777)).unwrap(),
            "nonexec" => fs::set_permissions(helper, fs::Permissions::from_mode(0o600)).unwrap(),
            "helperdir" => {
                fs::set_permissions(&f.helpers, fs::Permissions::from_mode(0o777)).unwrap()
            }
            _ => unreachable!(),
        }
        assert!(
            qualify_candidates(&[f.candidate(GitSelectionSource::Cli)], &ACCESS).is_err(),
            "{kind}"
        );
    }
}

#[test]
fn fake_git_changed_binding_refuses_before_dispatch_and_after_preparation() {
    for change in [
        "program",
        "program-replacement",
        "symlink",
        "helper",
        "route",
    ] {
        let f = FakeGit::new();
        let alias = f.root.path().join("alias");
        symlink(&f.program, &alias).unwrap();
        let selection = qualify_candidates(
            &[GitCandidate {
                path: alias.clone(),
                source: GitSelectionSource::Cli,
            }],
            &ACCESS,
        )
        .unwrap();
        let marker = f.root.path().join("dispatch-marker");
        let prepared = selection
            .binding
            .command(["status"], |cmd| {
                cmd.env("MARKER", &marker);
            })
            .unwrap();
        match change {
            "program" => f.script("git version 2.56.0", "touch \"$MARKER\""),
            "program-replacement" => {
                fs::rename(&f.program, f.root.path().join("old-git")).unwrap();
                f.script("git version 2.55.0", "touch \"$MARKER\"");
            }
            "symlink" => {
                fs::remove_file(&alias).unwrap();
                symlink(&f.program, &alias).unwrap();
            }
            "helper" => {
                let helper = f.helpers.join(REQUIRED_HELPERS[0]);
                fs::rename(&helper, helper.with_extension("old")).unwrap();
                fs::write(helper, "replacement").unwrap();
            }
            "route" => {
                fs::rename(&f.helpers, f.root.path().join("old-helpers")).unwrap();
                fs::create_dir(&f.helpers).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(selection.binding.revalidate().is_err(), "{change}");
        let failure = prepared
            .output_aggregate(Duration::from_secs(1), 1024)
            .unwrap_err();
        assert!(!failure.possibly_executed, "{change}");
        assert_eq!(failure.error.reason, GitBindingReason::Changed);
        assert!(!marker.exists());
    }
}

#[test]
fn fake_git_post_dispatch_changes_and_transport_failure_are_possibly_executed() {
    let f = FakeGit::new();
    f.script(
        "git version 2.55.0",
        "if [ \"$1\" = mutate ]; then chmod 600 \"$0\"; exit 0; fi",
    );
    let selected = bind(&f);
    let failure = selected
        .binding
        .command(["mutate"], |_| {})
        .unwrap()
        .output_aggregate(Duration::from_secs(1), 1024)
        .unwrap_err();
    assert!(failure.possibly_executed);
    assert_eq!(failure.error.reason, GitBindingReason::Changed);
    let f = FakeGit::new();
    f.script(
        "git version 2.55.0",
        "if [ \"$1\" = large ]; then head -c 4096 /dev/zero; fi",
    );
    let selected = bind(&f);
    let failure = selected
        .binding
        .command(["large"], |_| {})
        .unwrap()
        .output_aggregate(Duration::from_secs(1), 100)
        .unwrap_err();
    assert!(failure.possibly_executed);
    assert!(matches!(
        failure.error.reason,
        GitBindingReason::ProcessIncomplete(_)
    ));
}

#[test]
fn fake_git_ambiguous_or_changed_probes_abort_default_selection() {
    for extra in ["head -c 10000 /dev/zero", "sleep 3", "chmod 600 \"$0\""] {
        let bad = FakeGit::new();
        bad.script("git version 2.55.0", extra);
        let good = FakeGit::new();
        let marker = good.root.path().join("executed");
        good.script(
            "git version 2.55.0",
            &format!("touch '{}'", marker.display()),
        );
        let failure = qualify_candidates(
            &[
                bad.candidate(GitSelectionSource::PlatformDefault),
                good.candidate(GitSelectionSource::PlatformDefault),
            ],
            &ACCESS,
        )
        .unwrap_err();
        assert_eq!(failure.rejections.len(), 1);
        assert!(failure.ambiguous);
        assert!(!marker.exists());
    }
}

#[test]
fn fake_git_exec_path_preserves_non_utf8_bytes_and_hardlinked_helpers() {
    let mut f = FakeGit::new();
    let program = f.root.path().join(OsStr::from_bytes(b"git-\xff"));
    fs::rename(&f.program, &program).unwrap();
    f.program = program;
    let helpers = f.root.path().join(OsStr::from_bytes(b"helpers-\xff"));
    fs::rename(&f.helpers, &helpers).unwrap();
    f.helpers = helpers;
    let mut script =
        b"#!/bin/sh\ncase \"$1\" in --version) echo 'git version 2.55.0';; *) printf '%s\\n' '"
            .to_vec();
    script.extend_from_slice(f.helpers.as_os_str().as_bytes());
    script.extend_from_slice(b"';; esac\n");
    fs::write(&f.program, script).unwrap();
    fs::remove_file(f.helpers.join(REQUIRED_HELPERS[1])).unwrap();
    fs::hard_link(
        f.helpers.join(REQUIRED_HELPERS[0]),
        f.helpers.join(REQUIRED_HELPERS[1]),
    )
    .unwrap();
    let selected = bind(&f);
    assert_eq!(
        selected.binding.helper_directory.as_os_str().as_bytes(),
        f.helpers.as_os_str().as_bytes()
    );
    selected.binding.revalidate().unwrap();
}

#[test]
fn fake_git_access_unproven_refuses_before_probes() {
    #[derive(Debug)]
    struct Unproven;
    impl GitAccessProof for Unproven {
        fn prove(&self, path: &Path, _: &fs::Metadata) -> Result<(), GitBindingError> {
            Err(error(path, GitBindingReason::AccessUnproven))
        }
    }
    let f = FakeGit::new();
    let marker = f.root.path().join("executed");
    f.script(
        "git version 2.55.0",
        &format!("touch '{}'", marker.display()),
    );
    let failure =
        qualify_candidates(&[f.candidate(GitSelectionSource::Cli)], &Unproven).unwrap_err();
    assert_eq!(
        failure.rejections[0].error.reason,
        GitBindingReason::AccessUnproven
    );
    assert!(!marker.exists());
}

#[test]
fn fake_git_probes_are_sanitized_repository_free_and_dispatch_succeeds() {
    let f = FakeGit::new();
    f.script("git version 2.55.0", "[ \"$PWD\" = / ] || exit 10\n[ \"$PATH\" = /usr/bin:/bin:/usr/sbin:/sbin ] || exit 11\n[ \"$GIT_CONFIG_NOSYSTEM\" = 1 ] || exit 12\n[ \"$GIT_CONFIG_GLOBAL\" = /dev/null ] || exit 13\n[ \"$GIT_TERMINAL_PROMPT\" = 0 ] || exit 14\n[ \"$HOME\" = /nonexistent ] || exit 15\n[ \"$LC_ALL\" = C ] || exit 16\n[ -z \"$GIT_DIR$GIT_WORK_TREE$GIT_CONFIG_COUNT$GIT_SSH_COMMAND\" ] || exit 17\nif [ \"$1\" = environment ]; then printf '%s' \"$GIT_EXEC_PATH:$CALLER_RESTRICTION\"; exit 0; fi");
    let selected = bind(&f);
    let output = selected
        .binding
        .command(["environment"], |cmd| {
            cmd.env("CALLER_RESTRICTION", "preserved");
        })
        .unwrap()
        .output_aggregate(Duration::from_secs(1), 1024)
        .unwrap();
    assert!(output.status.success());
    let mut expected = f.helpers.as_os_str().as_bytes().to_vec();
    expected.extend_from_slice(b":preserved");
    assert_eq!(output.stdout, expected);
}

#[test]
fn fake_git_executable_change_during_rejected_helper_observation_aborts_selection() {
    #[derive(Debug)]
    struct ChangingAccess {
        program: PathBuf,
        helpers: PathBuf,
    }
    impl GitAccessProof for ChangingAccess {
        fn prove(&self, path: &Path, metadata: &fs::Metadata) -> Result<(), GitBindingError> {
            ACCESS.prove(path, metadata)?;
            if path == self.helpers {
                fs::set_permissions(&self.program, fs::Permissions::from_mode(0o600)).unwrap();
                return Err(error(path, GitBindingReason::UnsafeAccess));
            }
            Ok(())
        }
    }
    let bad = FakeGit::new();
    let good = FakeGit::new();
    let access = ChangingAccess {
        program: bad.program.clone(),
        helpers: bad.helpers.clone(),
    };
    let result = qualify_candidates(
        &[
            bad.candidate(GitSelectionSource::PlatformDefault),
            good.candidate(GitSelectionSource::PlatformDefault),
        ],
        &access,
    );
    let failure = result.unwrap_err();
    assert!(failure.ambiguous);
    assert_eq!(failure.rejections.len(), 1);
    assert_eq!(
        failure.rejections[0].error.reason,
        GitBindingReason::Changed
    );
}

#[test]
#[cfg(target_os = "linux")]
fn linux_git_access_proof_accepts_masked_acl_modes_and_rejects_foreign_writers() {
    let path = Path::new("/fixture");
    for (uid, mode, directory, symlink, accepted) in [
        (501, 0o755, false, false, true),
        (0, 0o755, false, false, true),
        (502, 0o755, false, false, false),
        (501, 0o775, false, false, false),
        (501, 0o757, false, false, false),
        (0, 0o1777, true, false, true),
        (502, 0o1777, true, false, false),
        (0, 0o777, true, false, false),
        (501, 0o777, false, true, true),
        (502, 0o777, false, true, false),
    ] {
        assert_eq!(
            linux_access_policy(path, uid, mode, directory, symlink, 501).is_ok(),
            accepted,
            "{uid} {mode:o}"
        );
    }
}

#[test]
fn system_git_access_refuses_missing_candidate_without_probe() {
    // Missing input is tested through the real service without executing a real
    // repository's Git or pretending fake-owner mode is qualification evidence.
    let f = FakeGit::new();
    fs::remove_file(&f.program).unwrap();
    let failure = select_git(&[f.candidate(GitSelectionSource::Cli)]).unwrap_err();
    assert!(!failure.ambiguous);
    assert_eq!(
        failure.rejections[0].candidate.path.as_os_str().as_bytes(),
        f.program.as_os_str().as_bytes()
    );
}

#[test]
fn fake_git_profile_cannot_replace_selected_executable_or_helper_binding() {
    let f = FakeGit::new();
    let selected = bind(&f);
    let result = selected.binding.command(["status"], |cmd| {
        *cmd = Command::new("/unrelated/git");
    });
    assert!(matches!(
        result,
        Err(GitBindingError {
            reason: GitBindingReason::CommandProfile,
            ..
        })
    ));
    let prepared = selected
        .binding
        .command(["status"], |cmd| {
            cmd.env("GIT_EXEC_PATH", "/unrelated/helpers");
        })
        .unwrap();
    let env: Vec<_> = prepared.command.get_envs().collect();
    assert!(env.contains(&(OsStr::new("GIT_EXEC_PATH"), Some(f.helpers.as_os_str()))));
}

#[test]
fn fake_git_signalled_probe_is_not_a_clean_nonzero_rejection() {
    let bad = FakeGit::new();
    bad.script("git version 2.55.0", "kill -TERM $$");
    let good = FakeGit::new();
    let marker = good.root.path().join("executed");
    good.script(
        "git version 2.55.0",
        &format!("touch '{}'", marker.display()),
    );
    let failure = qualify_candidates(
        &[
            bad.candidate(GitSelectionSource::PlatformDefault),
            good.candidate(GitSelectionSource::PlatformDefault),
        ],
        &ACCESS,
    )
    .unwrap_err();
    assert!(failure.ambiguous);
    assert_eq!(failure.rejections.len(), 1);
    assert!(!marker.exists());
}

#[test]
fn fake_git_intermediate_relative_symlink_and_ancestor_replacement_are_bound() {
    let f = FakeGit::new();
    let prefix = f.root.path().join("prefix");
    fs::create_dir_all(prefix.join("bin")).unwrap();
    symlink("../../git", prefix.join("bin/git")).unwrap();
    let spelling = prefix.join("bin/../bin/git");
    let selected = qualify_candidates(
        &[GitCandidate {
            path: spelling.clone(),
            source: GitSelectionSource::Cli,
        }],
        &ACCESS,
    )
    .unwrap();
    assert_eq!(
        selected.binding.candidate().path.as_os_str().as_bytes(),
        spelling.as_os_str().as_bytes()
    );
    assert_eq!(selected.binding.canonical_program(), f.program);
    fs::rename(&prefix, f.root.path().join("old-prefix")).unwrap();
    fs::create_dir_all(prefix.join("bin")).unwrap();
    symlink("../../git", prefix.join("bin/git")).unwrap();
    assert_eq!(
        selected.binding.revalidate().unwrap_err().reason,
        GitBindingReason::Changed
    );
}

#[test]
fn fake_git_strict_version_and_overlong_exec_path_are_not_trimmed_into_validity() {
    for script in [
        "printf 'git version 2.55.0'",
        "printf 'git version 2.55.0\\nextra\\n'",
        "printf 'git version 02.55.0\\n'",
        "printf 'git version 2.55.0-rc0\\n'",
        "if [ \"$1\" = --version ]; then echo 'git version 2.55.0'; else printf /; head -c 5000 /dev/zero | tr '\\000' a; printf '\\n'; fi",
    ] {
        let f = FakeGit::new();
        fs::write(&f.program, format!("#!/bin/sh\n{script}\n")).unwrap();
        let failure = qualify_candidates(&[f.candidate(GitSelectionSource::Cli)], &ACCESS).unwrap_err();
        assert!(!failure.ambiguous);
    }
}

#[test]
#[cfg(target_os = "linux")]
fn fake_git_owned_fixture_qualifies_through_real_linux_access_service() {
    let f = FakeGit::new();
    let selected = select_git(&[f.candidate(GitSelectionSource::Cli)]).unwrap();
    assert_eq!(
        selected.binding.version(),
        GitVersion {
            major: 2,
            minor: 55,
            patch: 0
        }
    );
    assert_eq!(selected.binding.helper_directory(), f.helpers);
    let output = selected
        .binding
        .command(["status"], |_| {})
        .unwrap()
        .output_aggregate(Duration::from_secs(1), 1024)
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"dispatch");
}

#[test]
#[cfg(target_os = "macos")]
fn fake_git_darwin_access_is_explicitly_unproven_before_execution() {
    let f = FakeGit::new();
    let marker = f.root.path().join("executed");
    f.script(
        "git version 2.55.0",
        &format!("touch '{}'", marker.display()),
    );
    let failure = select_git(&[f.candidate(GitSelectionSource::Cli)]).unwrap_err();
    assert_eq!(
        failure.rejections[0].error.reason,
        GitBindingReason::AccessUnproven
    );
    assert!(!marker.exists());
}
