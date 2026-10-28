//! Source-only contracts; execution requires separately authorized isolated CI.
use work_cli as work_cli_api;
use work_cli::disposal::{self, PolicyDocument, RawPath};

#[path = "support/inspection_fixture.rs"]
mod fixture;

#[test]
fn actual_ignored_policy_matching_requires_every_descendant() {
    use std::{fs, os::unix::fs::PermissionsExt};
    use work_cli::inspection::{Coverage, FindingKind};
    for case in [
        "exact",
        "secret",
        "missing-directory",
        "untracked",
        "tracked",
        "pyc",
        "marker",
        "mode",
    ] {
        let mut f = fixture::ManagedFixture::new("sha1", "2");
        fs::create_dir_all(f.path(b"cache/empty")).unwrap();
        fs::write(f.path(b"cache/a"), b"abc").unwrap();
        fs::set_permissions(f.path(b"cache/a"), fs::Permissions::from_mode(0o600)).unwrap();
        match case {
            "secret" | "pyc" | "marker" => {
                fs::write(f.path(format!("cache/{case}").as_bytes()), b"private").unwrap()
            }
            "missing-directory" => fs::remove_dir(f.path(b"cache/empty")).unwrap(),
            "untracked" => fs::write(f.path(b".gitignore"), b"").unwrap(),
            "tracked" => f.git(&["add".as_ref(), "-f".as_ref(), "cache/a".as_ref()]),
            "mode" => {
                fs::set_permissions(f.path(b"cache/a"), fs::Permissions::from_mode(0o644)).unwrap()
            }
            _ => (),
        }
        let observation = f.inspect(&disposal::validate(document()).unwrap());
        assert_eq!(
            observation.coverage(),
            Coverage::Complete,
            "{case}: {:?}",
            observation.reasons()
        );
        let matched = observation
            .entries()
            .iter()
            .find(|e| e.path().as_bytes() == b"cache/a")
            .unwrap()
            .policy_match();
        assert_eq!(matched.is_some(), case == "exact", "{case}");
        if case != "exact" {
            assert!(!observation.findings().is_empty(), "{case}");
        }
        if case == "untracked" {
            assert!(observation
                .findings()
                .iter()
                .any(|v| v.kind() == FindingKind::Untracked));
        }
    }
}

#[test]
fn missing_scope_is_a_finding_not_a_successful_policy() {
    let mut f = fixture::ManagedFixture::new("sha1", "2");
    let observation = f.inspect(&disposal::validate(document()).unwrap());
    assert_eq!(
        observation.coverage(),
        work_cli::inspection::Coverage::Complete,
        "{:?}",
        observation.reasons()
    );
    assert!(observation.findings().iter().any(|f| f.kind()
        == work_cli::inspection::FindingKind::PolicyMismatch
        && f.path().as_bytes() == b"cache"));
    assert!(observation
        .entries()
        .iter()
        .all(|e| e.policy_match().is_none()));
}

fn document() -> PolicyDocument {
    serde_json::from_value(serde_json::json!({
        "format": 1,
        "policies": [{"id":"build-output", "version":"1", "scope":"6361636865",
            "max_files":1, "max_file_bytes":3, "max_total_bytes":3,
            "directories":["6361636865", "63616368652f656d707479"],
            "files":[{"path":"63616368652f61", "sha256":
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                "length":3, "mode":384}]}]
    }))
    .unwrap()
}

#[test]
fn policy_requires_exact_content_and_directory_coverage() {
    // Positive validation is NOT evidence that these files exist or are ignored.
    assert!(disposal::validate(document()).is_ok());
    let mut missing = document();
    missing.policies[0].directories.clear();
    assert!(disposal::validate(missing).is_err());
    for field in ["mode", "length", "hash", "overlap", "duplicate", "parent"] {
        let mut d = document();
        match field {
            "mode" => d.policies[0].files[0].mode = 0o4600,
            "length" => d.policies[0].files[0].length = 4,
            "hash" => d.policies[0].files[0].sha256 = "AA".repeat(32),
            "overlap" => {
                let mut p = d.policies[0].clone();
                p.id = "other".into();
                d.policies.push(p);
            }
            "duplicate" => {
                let p = d.policies[0].files[0].clone();
                d.policies[0].files.push(p);
            }
            "parent" => d.policies[0].files[0].path = "63616368652f7375622f61".into(),
            _ => unreachable!(),
        }
        assert!(disposal::validate(d).is_err(), "{field}");
    }
    assert!(
        serde_json::from_str::<PolicyDocument>(r#"{"format":1,"policies":[],"learn":true}"#)
            .is_err()
    );
    let mut d = document();
    d.format = 2;
    assert!(disposal::validate(d).is_err());
}

#[test]
fn raw_path_wire_rejects_aliases() {
    for wire in [
        "", "2F61", "2f61", "61/62", "61ffFf", "0", "00", "2e", "2e2e", "612f", "612f2f62",
        "612f2e", "612f2e2e",
    ] {
        assert!(RawPath::from_hex(wire).is_err(), "{wire}");
    }
    for bytes in [b"-name".as_slice(), b"cache/\xff\n\t", b"arbitrary.pyc"] {
        let path = RawPath::from_bytes(bytes).unwrap();
        assert_eq!(RawPath::from_hex(&path.to_hex()).unwrap().as_bytes(), bytes);
        let json = serde_json::to_string(&path).unwrap();
        assert_eq!(serde_json::from_str::<RawPath>(&json).unwrap(), path);
    }
    assert!(RawPath::from_bytes(&vec![b'a'; 4096]).is_ok());
    assert!(RawPath::from_bytes(&vec![b'a'; 4097]).is_err());
    let at = vec!["a"; 64].join("/");
    assert!(RawPath::from_bytes(at.as_bytes()).is_ok());
    assert!(RawPath::from_bytes(format!("{at}/a").as_bytes()).is_err());
}

#[test]
fn policy_body_and_version_change_digest() {
    let original = disposal::validate(document()).unwrap();
    let mut reordered = document();
    reordered.policies[0].directories.reverse();
    assert_eq!(
        original.digest(),
        disposal::validate(reordered).unwrap().digest()
    );
    for field in ["version", "id", "mode", "hash", "max_files", "directory"] {
        let mut d = document();
        match field {
            "version" => d.policies[0].version = "2".into(),
            "id" => d.policies[0].id = "different".into(),
            "mode" => d.policies[0].files[0].mode = 0o644,
            "hash" => d.policies[0].files[0].sha256 = "00".repeat(32),
            "max_files" => d.policies[0].max_files = 2,
            "directory" => d.policies[0]
                .directories
                .push("63616368652f6f74686572".into()),
            _ => unreachable!(),
        }
        assert_ne!(
            original.digest(),
            disposal::validate(d).unwrap().digest(),
            "{field}"
        );
    }
}

#[test]
fn policy_parser_and_canonical_body_are_bounded() {
    let bytes = serde_json::to_vec(&document()).unwrap();
    assert!(disposal::parse_document(&bytes).is_ok());
    assert!(disposal::parse_document(&vec![b' '; 1024 * 1024 + 1]).is_err());
    let mut d = document();
    let template = d.policies[0].files[0].clone();
    d.policies[0].files.clear();
    d.policies[0].max_files = 256;
    d.policies[0].max_total_bytes = 768;
    for n in 0..256 {
        let mut file = template.clone();
        let raw = format!("cache/{n:03}{}", "x".repeat(4080));
        file.path = RawPath::from_bytes(raw.as_bytes()).unwrap().to_hex();
        d.policies[0].files.push(file);
    }
    // Structurally valid proposal, but its canonical framing exceeds 1 MiB.
    assert!(disposal::validate(d).is_err());
}

#[test]
fn policy_limits_are_validation_not_content_proof() {
    for field in [
        "id",
        "version",
        "files",
        "file_bytes",
        "total_bytes",
        "rules",
    ] {
        let mut d = document();
        match field {
            "id" => d.policies[0].id = "a".repeat(129),
            "version" => d.policies[0].version = "a".repeat(129),
            "files" => d.policies[0].max_files = 4097,
            "file_bytes" => d.policies[0].max_file_bytes = 16 * 1024 * 1024 + 1,
            "total_bytes" => d.policies[0].max_total_bytes = 128 * 1024 * 1024 + 1,
            "rules" => d.policies = vec![d.policies[0].clone(); 65],
            _ => unreachable!(),
        }
        assert!(disposal::validate(d).is_err(), "{field}");
    }
    let empty = PolicyDocument {
        format: 1,
        policies: vec![],
    };
    assert!(disposal::validate(empty).is_ok());
}
