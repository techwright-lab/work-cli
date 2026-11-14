use super::*;
use std::path::{Path, PathBuf};

#[test]
fn git_version_admits_canonical_stable_releases_at_or_above_floor() {
    for (output, expected) in [
        (b"git version 2.55.0\n".as_slice(), (2, 55, 0)),
        (b"git version 2.56.0\n", (2, 56, 0)),
        (b"git version 2.55.1\n", (2, 55, 1)),
        (b"git version 3.0.0\n", (3, 0, 0)),
        (
            b"git version 4294967295.4294967295.4294967295\n",
            (u32::MAX, u32::MAX, u32::MAX),
        ),
    ] {
        assert_eq!(
            require_supported_git_version(output),
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
fn git_version_reports_canonical_below_floor_separately() {
    for (output, version) in [
        (b"git version 0.0.0\n".as_slice(), (0, 0, 0)),
        (b"git version 1.99.99\n", (1, 99, 99)),
        (b"git version 2.54.4294967295\n", (2, 54, u32::MAX)),
    ] {
        assert_eq!(
            require_supported_git_version(output),
            Err(GitVersionError::BelowMinimum {
                found: GitVersion {
                    major: version.0,
                    minor: version.1,
                    patch: version.2,
                },
                minimum: GitVersion {
                    major: 2,
                    minor: 55,
                    patch: 0,
                },
            }),
            "{output:?}"
        );
    }
}

#[test]
fn git_version_rejects_noncanonical_byte_protocol() {
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
        b"git version 2.55.0.1\n",
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
        b"git version 2.55.0 (Apple Git-123)\n",
        b"git version 2.55.0.vendor\n",
        b"git version 2.55.0 \n",
        b"git version 2.55.0\t\n",
        b"git version 2.55.0\0\n",
        b"git version 2.55.\xff\n",
        b"git version 4294967296.55.0\n",
        b"git version 2.4294967296.0\n",
        b"git version 2.55.4294967296\n",
    ] {
        assert_eq!(
            require_supported_git_version(output),
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
