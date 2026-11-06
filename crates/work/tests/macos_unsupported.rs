//! Native development boundary only: no Git, authority initialization or lifecycle qualification.
#![cfg(target_os = "macos")]

use std::{
    collections::BTreeMap, ffi::OsString, fs, os::unix::fs::MetadataExt, path::Path,
    process::Command,
};

#[derive(Debug, PartialEq, Eq)]
struct Entry {
    bytes: Vec<u8>,
    identity: (u64, u64),
    mode: u32,
    modified: (i64, i64),
    changed: (i64, i64),
}

fn snapshot(root: &Path) -> BTreeMap<std::path::PathBuf, Entry> {
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        let metadata = fs::symlink_metadata(&path).unwrap();
        let entry = Entry {
            bytes: if metadata.is_dir() {
                Vec::new()
            } else {
                fs::read(&path).unwrap()
            },
            identity: (metadata.dev(), metadata.ino()),
            mode: metadata.mode(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        };
        files.insert(path.clone(), entry);
        if metadata.is_dir() {
            files.extend(snapshot(&path));
        }
    }
    files
}

fn invoke(args: &[OsString]) -> std::process::Output {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    for name in [
        "home",
        "config",
        "state",
        "registry",
        "authority",
        "artifacts",
        "tmp",
        "cache",
        "data",
    ] {
        fs::create_dir(root.join(name)).unwrap();
        fs::write(root.join(name).join("sentinel"), b"preserve\0history").unwrap();
    }
    let config = root.join("config/work.toml");
    fs::write(&config, b"deliberately invalid config; must not be loaded").unwrap();
    let before = snapshot(root);
    let output = Command::new(env!("CARGO_BIN_EXE_work"))
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", root.join("home"))
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("XDG_STATE_HOME", root.join("state"))
        .env("XDG_CACHE_HOME", root.join("cache"))
        .env("XDG_DATA_HOME", root.join("data"))
        .env("TMPDIR", root.join("tmp"))
        .env("WORK_CONFIG", &config)
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(snapshot(root), before, "must not mutate fixture: {args:?}");
    output
}

#[test]
fn help_and_version_need_no_git_or_authority() {
    for arg in ["--help", "--version"] {
        let output = invoke(&[arg.into()]);
        assert!(output.status.success(), "{output:?}");
        assert!(!output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn supervision_refuses_before_config_context_or_child_execution() {
    for args in [
        vec![
            "run",
            "secret-checkout",
            "--",
            "/bin/sh",
            "-c",
            "touch child-launched",
        ],
        vec!["recover", "019281b2-67de-7000-8000-000000000001"],
        vec![
            "__scope-child",
            "--context",
            "secret-context",
            "--",
            "/bin/sh",
            "-c",
            "touch child-launched",
        ],
        vec!["run", "--secret-invalid-option"],
        vec!["__scope-child", "secret-malformed-context"],
    ] {
        let output = invoke(&args.iter().map(OsString::from).collect::<Vec<_>>());
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let diagnostic = String::from_utf8(output.stderr).unwrap();
        assert!(diagnostic.contains("unsupported on macOS"), "{diagnostic}");
        for secret in ["secret-", "touch", "child-launched"] {
            assert!(
                !diagnostic.contains(secret),
                "must redact argv: {diagnostic}"
            );
        }
    }
}

#[test]
fn incomplete_native_core_refuses_before_loading_or_mutating_authority() {
    for args in [
        vec!["setup"],
        vec!["start", "--task", "secret-task", "--base", "main"],
        vec!["finish", "secret-checkout"],
        vec!["remove", "secret-checkout", "--confirm-stopped"],
        vec![
            "inspect",
            "019281b2-67de-7000-8000-000000000001",
            "--record",
        ],
        vec!["capture", "secret-invalid-subcommand"],
        vec!["participant", "secret-invalid-subcommand"],
        vec!["adopt", "secret-invalid-subcommand"],
        vec!["retire", "secret-invalid-subcommand"],
        vec!["prepare-recovery", "019281b2-67de-7000-8000-000000000001"],
        vec!["verify-remote", "019281b2-67de-7000-8000-000000000001"],
        vec!["audit-preservation", "019281b2-67de-7000-8000-000000000001"],
        vec!["approve", "secret-invalid-subcommand"],
    ] {
        let output = invoke(&args.iter().map(OsString::from).collect::<Vec<_>>());
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let diagnostic = String::from_utf8(output.stderr).unwrap();
        assert!(
            diagnostic.contains("native backend incomplete"),
            "{diagnostic}"
        );
        assert!(!diagnostic.contains("secret-"));
    }
}

#[test]
fn scope_child_library_refuses_before_collecting_or_publishing() {
    struct MustNotObserve;
    impl work_cli::scope_child::LibraryCollector for MustNotObserve {
        fn identities(
            &self,
        ) -> Result<
            (
                work_cli::runtime_scope::ChildIdentity,
                work_cli::runtime_scope::ChildIdentity,
            ),
            &'static str,
        > {
            panic!("unsupported child must not collect identities");
        }
    }
    let fixture = tempfile::tempdir().unwrap();
    let context = fixture.path().join("context.json");
    fs::write(&context, b"not a context; must not be parsed or replaced").unwrap();
    let before = snapshot(fixture.path());
    assert_eq!(
        work_cli::scope_child::run_with_collector(
            &context,
            &["/bin/sh".into(), "-c".into(), "touch child-launched".into()],
            &MustNotObserve,
        ),
        Err("scope child unsupported on this platform"),
    );
    assert_eq!(snapshot(fixture.path()), before);
}

#[test]
fn mutable_store_admission_refuses_before_creating_registry_or_authority() {
    for method in ["open", "open_registered", "open_existing_registered_mut"] {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().canonicalize().unwrap();
        let managed = root.join("managed");
        fs::create_dir(&managed).unwrap();
        let registry = root.join(".work-authorities");
        let authority = root.join("authority");
        let before = snapshot(&root);
        let result = match method {
            "open" => work_cli::store::Store::open(&authority, &[managed]),
            "open_registered" => {
                work_cli::store::Store::open_registered(&registry, &authority, &[managed])
            }
            _ => work_cli::store::Store::open_existing_registered_mut(
                &registry,
                &authority,
                &[managed],
            ),
        };
        assert!(!registry.exists(), "{method} must not bootstrap a registry");
        assert!(
            !authority.exists(),
            "{method} must not create authority storage"
        );
        assert_eq!(
            snapshot(&root),
            before,
            "{method} must leave fixture unchanged"
        );
        let error = result.err().expect("native mutable authority must refuse");
        assert!(
            error
                .to_string()
                .contains("native mutable authority backend incomplete"),
            "{method}: {error}"
        );
    }
}

#[test]
fn native_allocation_refuses_before_registry_bootstrap() {
    use work_cli::{
        allocate::{self, Start},
        config::{AllocationPolicy, Config},
    };
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().canonicalize().unwrap();
    let managed = root.join("managed");
    let repository = root.join("repository");
    fs::create_dir(&managed).unwrap();
    fs::create_dir(&repository).unwrap(); // Not a Git repository: no Git may be dispatched.
    let registry = root.join("registry");
    let authority = root.join("authority");
    let config = Config {
        store_dir: Some(authority.clone()),
        trusted_registry: Some(registry.clone()),
        roots: vec![managed.clone()],
        repositories: vec![repository.clone()],
        allocation: Some(AllocationPolicy {
            repository_limit: 2,
            owner_limit: 2,
            floor_bytes: 1,
            warn_bytes: 2,
            capture_sink: None,
        }),
        ..Default::default()
    };
    let request = Start {
        operation: uuid::Uuid::parse_str("019281b2-67de-7000-8000-000000000001").unwrap(),
        repository: Some(repository),
        root: Some(managed),
        actor: Some("fixture".into()),
        owner: None,
        task: "native-refusal".into(),
        branch: None,
        base: "main".into(),
        reuse_branch: false,
    };
    let before = snapshot(&root);
    let result = allocate::start_observed(&config, request, |_| {
        panic!("must not reach persisted allocation boundary")
    });
    assert!(
        !registry.exists(),
        "allocation must not bootstrap a registry"
    );
    assert!(!authority.exists());
    assert_eq!(snapshot(&root), before);
    let error = result.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("native mutable authority backend incomplete"),
        "{error}"
    );
}

#[test]
fn passive_store_admission_is_not_replaced_by_mutable_backend_refusal() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().canonicalize().unwrap();
    let before = snapshot(&root);
    let error = work_cli::store::Store::open_existing_registered_readonly(
        &root.join("registry"),
        &root.join("authority"),
        &[],
    )
    .err()
    .expect("absent authority must not initialize");
    assert!(!error
        .to_string()
        .contains("native mutable authority backend incomplete"));
    assert_eq!(snapshot(&root), before);
}

// Each PATH-injected probe runs in its own test process; no process-global env mutation.
#[test]
fn linux_scope_probe_child() {
    let Some(case) = std::env::var_os("WORK_TEST_NATIVE_SCOPE_CASE") else {
        return;
    };
    let error = if case == "inspect" {
        work_cli::linux_scope::inspect_host().err()
    } else {
        let options = work_cli::linux_scope::QualificationOptions {
            run_id: if case == "invalid" {
                "secret\nvalue"
            } else {
                "native-refusal"
            },
            adapter: "fixture",
            opt_in_fixture: case == "opt-in",
        };
        work_cli::linux_scope::qualify(options).err()
    };
    assert!(
        !Path::new(&std::env::var_os("WORK_TEST_NATIVE_SCOPE_SENTINEL").unwrap()).exists(),
        "unsupported native probe must not execute helpers"
    );
    assert_eq!(
        error.expect("native probe must refuse").kind(),
        std::io::ErrorKind::Unsupported,
    );
}

#[test]
fn linux_scope_public_probes_refuse_before_any_helper_execution() {
    use std::os::unix::fs::PermissionsExt;
    for case in ["inspect", "passive", "opt-in", "invalid"] {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().canonicalize().unwrap();
        let bin = root.join("bin");
        fs::create_dir(&bin).unwrap();
        fs::create_dir(root.join("tmp")).unwrap();
        for name in ["systemctl", "git", "systemd-run"] {
            let helper = bin.join(name);
            fs::write(
                &helper,
                b"#!/bin/sh\nprintf executed >> \"$WORK_TEST_NATIVE_SCOPE_SENTINEL\"\nexit 1\n",
            )
            .unwrap();
            fs::set_permissions(helper, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let before = snapshot(&root);
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "linux_scope_probe_child", "--nocapture"])
            .env_clear()
            .env("PATH", &bin)
            .env("HOME", &root)
            .env("TMPDIR", root.join("tmp"))
            .env("WORK_TEST_NATIVE_SCOPE_CASE", case)
            .env(
                "WORK_TEST_NATIVE_SCOPE_SENTINEL",
                root.join("helper-executed"),
            )
            .current_dir(&root)
            .output()
            .unwrap();
        assert!(output.status.success(), "{case}: {output:?}");
        assert_eq!(snapshot(&root), before);
    }
}
