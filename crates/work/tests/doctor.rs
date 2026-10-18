use serde_json::Value;
use std::{collections::BTreeMap, fs, os::unix::fs::symlink, path::Path, process::Command};
use work_cli::{
    admission::{Limits, Reservation},
    store::Store,
};

fn git(path: &Path, args: &[&str]) {
    let o = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
}
struct Fixture {
    temp: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        for name in ["repo", "roots"] {
            fs::create_dir(temp.path().join(name)).unwrap();
        }
        let repo = temp.path().join("repo");
        git(&repo, &["init", "-q"]);
        git(
            &repo,
            &[
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "--allow-empty",
                "-qm",
                "initial",
            ],
        );
        git(
            &repo,
            &[
                "worktree",
                "add",
                "-qb",
                "linked",
                temp.path().join("roots/linked").to_str().unwrap(),
            ],
        );
        Self { temp }
    }
    fn p(&self, s: &str) -> std::path::PathBuf {
        self.temp.path().join(s)
    }
    fn run(&self, extra: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_work"))
            .args(["doctor", "--json", "--repository"])
            .arg(self.p("repo"))
            .arg("--managed-root")
            .arg(self.p("roots"))
            .arg("--store-dir")
            .arg(self.p("store"))
            .arg("--trusted-registry")
            .arg(self.p("registry"))
            .args(extra)
            .env("WORK_CONFIG", "")
            .output()
            .unwrap()
    }
    fn report(&self, extra: &[&str]) -> Value {
        let o = self.run(extra);
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        serde_json::from_slice(&o.stdout).unwrap()
    }
}
fn snapshot(path: &Path) -> BTreeMap<std::path::PathBuf, Vec<u8>> {
    fn walk(p: &Path, out: &mut BTreeMap<std::path::PathBuf, Vec<u8>>) {
        for e in fs::read_dir(p).unwrap() {
            let p = e.unwrap().path();
            let m = fs::symlink_metadata(&p).unwrap();
            if m.file_type().is_symlink() {
                out.insert(p, vec![]);
            } else if m.is_dir() {
                out.insert(p.clone(), vec![]);
                walk(&p, out);
            } else {
                out.insert(p.clone(), fs::read(&p).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(path, &mut out);
    out
}
#[test]
fn inventory_deduplicates_aliases_reports_unmanaged_and_never_creates_missing_store() {
    let f = Fixture::new();
    fs::create_dir(f.p("roots/orphan")).unwrap();
    fs::write(f.p("roots/orphan/payload"), b"12345").unwrap();
    let before = snapshot(f.temp.path());
    let v = f.report(&["--repository", f.p("roots/linked").to_str().unwrap()]);
    assert_eq!(v["repositories"].as_array().unwrap().len(), 1);
    assert_eq!(v["accounting"]["status"], "unknown");
    assert!(v["accounting"]["reason"]
        .as_str()
        .unwrap()
        .contains("lack checkout filesystem paths"));
    let entries = v["inventory"].as_array().unwrap();
    assert_eq!(entries.len(), 3);
    assert!(entries.iter().any(|e| e["classification"] == "legacy"));
    assert!(entries
        .iter()
        .any(|e| e["classification"] == "unmanaged" && e["logical_bytes"] == 5));
    assert!(v["headroom"][0]["available_bytes"].as_u64().unwrap() > 0);
    let second = f.report(&[]);
    assert_eq!(v["inventory"], second["inventory"]);
    assert_eq!(before, snapshot(f.temp.path()));
}
#[test]
fn rejects_ambiguous_roots_and_config_types_without_leaking_values() {
    let f = Fixture::new();
    symlink(f.p("roots"), f.p("alias")).unwrap();
    for root in [f.p("alias"), f.p("roots/linked")] {
        let o = f.run(&["--managed-root", root.to_str().unwrap()]);
        assert!(!o.status.success());
    }
    for text in [
        "roots = 'private-secret'",
        "repositories = [42]",
        "store_dir = 42",
        "trusted_registry = false",
    ] {
        fs::write(f.p("config.toml"), text).unwrap();
        let o = Command::new(env!("CARGO_BIN_EXE_work"))
            .args(["doctor", "--json"])
            .env("WORK_CONFIG", f.p("config.toml"))
            .output()
            .unwrap();
        assert!(!o.status.success());
        assert!(!String::from_utf8_lossy(&o.stderr).contains("private-secret"));
    }
}
#[test]
fn malformed_pointer_missing_private_metadata_and_symlink_payload_are_unknown() {
    for case in [
        "pointer",
        "metadata",
        "private_deleted",
        "symlink",
        "unregistered_bad_pointer",
    ] {
        let f = Fixture::new();
        match case {
            "pointer" => fs::write(f.p("roots/linked/.git"), "not a git pointer\n").unwrap(),
            "metadata" => fs::remove_file(f.p("repo/.git/worktrees/linked/HEAD")).unwrap(),
            "private_deleted" => fs::remove_dir_all(f.p("repo/.git/worktrees/linked")).unwrap(),
            "unregistered_bad_pointer" => {
                fs::create_dir(f.p("roots/bad")).unwrap();
                fs::write(f.p("roots/bad/.git"), "gitdir: /untrusted/private-secret\n").unwrap();
            }
            _ => symlink(f.p("repo"), f.p("roots/escape")).unwrap(),
        }
        let before = snapshot(f.temp.path());
        let v = f.report(&[]);
        let expected = match case {
            "symlink" => f.p("roots/escape"),
            "unregistered_bad_pointer" => f.p("roots/bad"),
            _ => f.p("roots/linked"),
        };
        assert!(
            v["inventory"].as_array().unwrap().iter().any(
                |e| e["classification"] == "unknown" && e["path"] == expected.to_str().unwrap()
            ),
            "case={case}: {v}"
        );
        assert!(!v.to_string().contains("private-secret"));
        assert_eq!(before, snapshot(f.temp.path()));
    }
}
#[test]
fn existing_accounting_is_not_filesystem_certification_and_does_not_write_events() {
    let f = Fixture::new();
    let mut store =
        Store::open_registered(&f.p("registry"), &f.p("store"), &[f.p("roots")]).unwrap();
    store
        .reserve(
            &Reservation {
                operation: uuid::Uuid::now_v7(),
                repository: f.p("repo"),
                actor: "actor".into(),
                owner: "owner".into(),
                task: "task".into(),
            },
            Limits {
                repository: 10,
                owner: 10,
                available_bytes: Some(100),
                floor_bytes: 0,
                warn_bytes: 0,
            },
        )
        .unwrap();
    // A live registry reader keeps its WAL sidecars present too. A closed WAL
    // registry without sidecars is deliberately unknown rather than recreated.
    let registry = rusqlite::Connection::open(f.p("registry/authorities.sqlite")).unwrap();
    registry
        .query_row("SELECT count(*) FROM authorities", [], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap();
    let events = store.pending_events(100).unwrap().len();
    // Keep writer open: WAL/SHM must already exist. SHM lock bookkeeping is not byte immutability.
    let before = snapshot(f.temp.path());
    let before_paths: Vec<_> = before.keys().cloned().collect();
    let a = f.report(&[]);
    let b = f.report(&[]);
    assert_eq!(a["accounting"], b["accounting"]);
    assert_eq!(a["accounting"]["status"], "available");
    assert_eq!(a["accounting"]["charges"][0]["owner"], "owner");
    assert_eq!(a["accounting"]["charges"][0]["charged"], 1);
    assert!(a["managed_filesystem_count"].is_null());
    assert_eq!(events, store.pending_events(100).unwrap().len());
    assert_eq!(
        before_paths,
        snapshot(f.temp.path()).into_keys().collect::<Vec<_>>()
    );
    let after = snapshot(f.temp.path());
    for (path, bytes) in &before {
        if !path.to_string_lossy().ends_with("-shm") {
            assert_eq!(
                Some(bytes),
                after.get(path),
                "read-only report changed {path:?}"
            );
        }
    }
    symlink(f.p("missing-target"), f.p("store/store.sqlite-journal")).unwrap();
    assert_eq!(f.report(&[])["accounting"]["status"], "unknown");
    fs::remove_file(f.p("store/store.sqlite-journal")).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(f.p("registry"), fs::Permissions::from_mode(0o000)).unwrap();
    let inaccessible = f.report(&[]);
    fs::write(
        f.p("inaccessible.toml"),
        format!(
            "roots = [{:?}]\nrepositories = [{:?}]\nstore_dir = {:?}\ntrusted_registry = {:?}\n",
            f.p("roots"),
            f.p("repo"),
            f.p("registry/hidden"),
            f.p("registry")
        ),
    )
    .unwrap();
    let configured = Command::new(env!("CARGO_BIN_EXE_work"))
        .args(["doctor", "--json"])
        .env("WORK_CONFIG", f.p("inaccessible.toml"))
        .output()
        .unwrap();
    fs::remove_file(f.p("inaccessible.toml")).unwrap();
    fs::set_permissions(f.p("registry"), fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(inaccessible["accounting"]["status"], "unknown");
    assert!(
        configured.status.success(),
        "inaccessible accounting evidence is unknown, not invalid config"
    );
    let configured: Value = serde_json::from_slice(&configured.stdout).unwrap();
    assert_eq!(configured["accounting"]["status"], "unknown");
    assert_eq!(
        before_paths,
        snapshot(f.temp.path()).into_keys().collect::<Vec<_>>()
    );
    drop(store);
    drop(registry);
    let before = snapshot(f.temp.path());
    assert_eq!(f.report(&[])["accounting"]["status"], "unknown"); // closed WAL lacks sidecars: fail closed, don't create them
    assert_eq!(before, snapshot(f.temp.path()));
    fs::write(f.p("store/store.sqlite"), b"corrupt private-secret").unwrap();
    let before = snapshot(f.temp.path());
    let v = f.report(&[]);
    assert_eq!(v["accounting"]["status"], "unknown");
    assert!(!v.to_string().contains("private-secret"));
    assert_eq!(before, snapshot(f.temp.path()));
}
#[test]
fn config_supplies_explicit_scope_and_empty_doctor_fails() {
    let f = Fixture::new();
    assert!(!Command::new(env!("CARGO_BIN_EXE_work"))
        .arg("doctor")
        .env("WORK_CONFIG", "")
        .output()
        .unwrap()
        .status
        .success());
    fs::write(
        f.p("config.toml"),
        format!(
            "roots = [{:?}]\nrepositories = [{:?}]\nstore_dir = {:?}\ntrusted_registry = {:?}\n",
            f.p("roots"),
            f.p("repo"),
            f.p("store"),
            f.p("registry")
        ),
    )
    .unwrap();
    let before = snapshot(f.temp.path());
    let o = Command::new(env!("CARGO_BIN_EXE_work"))
        .args(["doctor", "--json"])
        .env("WORK_CONFIG", f.p("config.toml"))
        .output()
        .unwrap();
    assert!(o.status.success());
    assert_eq!(before, snapshot(f.temp.path()));
}
