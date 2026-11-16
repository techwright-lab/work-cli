use super::*;
use std::path::{Path, PathBuf};

#[test]
fn git_version_admits_any_release_with_optional_vendor_text() {
    for (output, expected) in [
        (b"git version 2.55.0\n".as_slice(), (2, 55, 0)),
        (b"git version 2.54.0 (Apple Git-157)\n", (2, 54, 0)),
        (b"git version 2.56.0.windows.1\n", (2, 56, 0)),
        (b"git version 2.48.1\n", (2, 48, 1)),
        (b"git version 1.7.1\n", (1, 7, 1)),
        (b"git version 0.0.0\n", (0, 0, 0)),
        (b"git version 3.0.0\n", (3, 0, 0)),
        (
            b"git version 4294967295.4294967295.4294967295\n",
            (u32::MAX, u32::MAX, u32::MAX),
        ),
    ] {
        assert_eq!(
            parse_git_version(output),
            Ok(GitVersion {
                major: expected.0,
                minor: expected.1,
                patch: expected.2,
            }),
            "{output:?}"
        );
    }
}

#[test]
fn git_version_rejects_lines_without_three_decimal_components() {
    for output in [
        b"".as_slice(),
        b"2.55.0\n",
        b"Git version 2.55.0\n",
        b" git version 2.55.0\n",
        b"git version 2.55.0",
        b"git version 2.55.0\r\n",
        b"git version 2.55.0\n\n",
        b"git version 2.55.0\nextra\n",
        b"git version 2.55\n",
        b"git version 2.55 (Apple Git-157)\n",
        b"git version .55.0\n",
        b"git version 2..0\n",
        b"git version 2.55.\n",
        b"git version 02.55.0\n",
        b"git version 2.055.0\n",
        b"git version 2.55.00\n",
        b"git version +2.55.0\n",
        b"git version 2.-55.0\n",
        b"git version 2.55.+0\n",
        b"git version 2.55.0-rc0\n",
        b"git version 2.55.x\n",
        b"git version 2.x.0\n",
        b"git version 2.55.0 \n",
        b"git version 2.55.0.\n",
        b"git version 2.55.0\t\n",
        b"git version 2.55.0\0\n",
        b"git version 2.55.0 (Apple\tGit)\n",
        b"git version 2.55.\xff\n",
        b"git version 4294967296.55.0\n",
        b"git version 2.4294967296.0\n",
        b"git version 2.55.4294967296\n",
    ] {
        assert_eq!(
            parse_git_version(output),
            Err(GitVersionError::InvalidProtocol),
            "{output:?}"
        );
    }
}

#[test]
fn git_candidates_use_only_the_ordered_platform_defaults() {
    assert_eq!(
        git_candidates(GitPlatform::MacOs, None, None),
        Ok(vec![
            GitCandidate {
                path: PathBuf::from("/opt/homebrew/bin/git"),
                source: GitSelectionSource::PlatformDefault,
            },
            GitCandidate {
                path: PathBuf::from("/usr/bin/git"),
                source: GitSelectionSource::PlatformDefault,
            },
        ])
    );
    assert_eq!(
        git_candidates(GitPlatform::Linux, None, None),
        Ok(vec![GitCandidate {
            path: PathBuf::from("/usr/bin/git"),
            source: GitSelectionSource::PlatformDefault,
        }])
    );
}

#[test]
fn git_candidates_cli_overrides_config_and_defaults_without_probing() {
    for platform in [GitPlatform::Linux, GitPlatform::MacOs] {
        for config in [
            None,
            Some(Path::new("/configured/git")),
            Some(Path::new("")),
        ] {
            assert_eq!(
                git_candidates(platform, Some(Path::new("/not-installed/git")), config),
                Ok(vec![GitCandidate {
                    path: PathBuf::from("/not-installed/git"),
                    source: GitSelectionSource::Cli,
                }])
            );
        }
    }
}

#[test]
fn git_candidates_config_overrides_defaults_without_probing() {
    for platform in [GitPlatform::Linux, GitPlatform::MacOs] {
        assert_eq!(
            git_candidates(platform, None, Some(Path::new("/configured/git"))),
            Ok(vec![GitCandidate {
                path: PathBuf::from("/configured/git"),
                source: GitSelectionSource::Config,
            }])
        );
    }
}

#[test]
fn git_candidates_invalid_explicit_selection_never_falls_back() {
    for platform in [GitPlatform::Linux, GitPlatform::MacOs] {
        for path in ["", "git", "./git", "../bin/git", "~/bin/git"] {
            for (cli, config, source) in [
                (Some(Path::new(path)), None, GitSelectionSource::Cli),
                (
                    Some(Path::new(path)),
                    Some(Path::new("/configured/git")),
                    GitSelectionSource::Cli,
                ),
                (None, Some(Path::new(path)), GitSelectionSource::Config),
            ] {
                assert_eq!(
                    git_candidates(platform, cli, config),
                    Err(GitCandidateError::NotAbsolute(GitCandidate {
                        path: PathBuf::from(path),
                        source,
                    })),
                    "{platform:?} {source:?} {path:?}"
                );
            }
        }
    }
}

#[test]
fn git_candidates_preserve_unqualified_absolute_path_bytes() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    for bytes in [
        b"/opt/homebrew/bin/git".as_slice(),
        b"/somewhere/../git",
        b"/somewhere/./git",
        b"//somewhere//git",
        b"/git with spaces",
        b"/non-utf8-\xff/git",
    ] {
        let path = Path::new(OsStr::from_bytes(bytes));
        let candidates = git_candidates(GitPlatform::MacOs, Some(path), None).unwrap();
        // Path equality normalizes some spellings; the diagnostic input must not.
        assert_eq!(candidates[0].path.as_os_str().as_bytes(), bytes);
        assert_eq!(
            git_candidates(GitPlatform::MacOs, Some(path), None),
            Ok(vec![GitCandidate {
                path: path.to_owned(),
                source: GitSelectionSource::Cli,
            }])
        );
    }
}

#[test]
fn failure_reason_quotes_the_error_after_git_hints() {
    let stderr = b"hint: Support for <GIT_DIR>/info/grafts is deprecated\nhint:\n\nfatal: cannot remove a locked working tree;\nuse 'remove -f -f'\n";
    assert_eq!(
        failure_reason("git worktree remove refused", stderr),
        "git worktree remove refused: fatal: cannot remove a locked working tree;"
    );
}
