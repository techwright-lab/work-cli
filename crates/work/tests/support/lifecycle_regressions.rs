// Shared assertions and disposable physical fixtures for lifecycle reads.
#[allow(dead_code)] // Shared fixture: not every historical-read test materializes Git.
pub fn git_fixture() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let root = temp.path().join("root");
    std::fs::create_dir(&repo).unwrap();
    std::fs::create_dir(&root).unwrap();
    for args in [
        vec!["init", "-b", "main"],
        vec!["config", "user.name", "Test"],
        vec!["config", "user.email", "test@example.invalid"],
        vec!["commit", "--allow-empty", "-m", "initial"],
    ] {
        let output = std::process::Command::new("/usr/bin/git")
            .current_dir(&repo)
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "private Git fixture failed");
    }
    (temp, repo, root)
}
/// Replace a disposable fixture directory with byte-identical files but fresh
/// inodes. Never follows links or accepts special files.
#[allow(dead_code)] // Only the physical-proof suite needs replacement fixtures.
pub fn replace_directory(path: &std::path::Path) {
    fn copy(from: &std::path::Path, to: &std::path::Path) {
        std::fs::create_dir(to).unwrap();
        for entry in std::fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                copy(&entry.path(), &to.join(entry.file_name()));
            } else {
                assert!(kind.is_file());
                std::fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
            }
        }
    }
    let old = path.with_extension("fixture-original");
    std::fs::rename(path, &old).unwrap();
    copy(&old, path);
}
pub fn files(dir: &std::path::Path) -> Vec<(std::path::PathBuf, Option<Vec<u8>>)> {
    fn collect(path: std::path::PathBuf, result: &mut Vec<(std::path::PathBuf, Option<Vec<u8>>)>) {
        let kind = std::fs::symlink_metadata(&path).unwrap().file_type();
        if kind.is_dir() {
            result.push((path.clone(), None));
            for entry in std::fs::read_dir(path).unwrap() {
                collect(entry.unwrap().path(), result);
            }
        } else {
            assert!(kind.is_file(), "unexpected authority entry: {path:?}");
            // SHM contains SQLite's normal reader lock bookkeeping.
            let bytes = if path.to_string_lossy().ends_with("-shm") {
                Vec::new()
            } else {
                std::fs::read(&path).unwrap()
            };
            result.push((path, Some(bytes)));
        }
    }
    let mut result = Vec::new();
    for sub in [".work-authorities", "private"] {
        collect(dir.join(sub), &mut result);
    }
    result.sort();
    result
}

#[test]
fn authority_snapshot_preserves_nested_lock_files_and_entry_types() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".work-authorities")).unwrap();
    let locks = dir.path().join("private/checkout-locks");
    std::fs::create_dir_all(&locks).unwrap();
    let lock = locks.join("checkout.lock");
    std::fs::write(&lock, b"").unwrap();
    let original = files(dir.path());
    assert!(original.contains(&(locks.clone(), None)));
    assert!(original.contains(&(lock.clone(), Some(Vec::new()))));
    assert_eq!(original, files(dir.path()));
    std::fs::write(&lock, b"changed").unwrap();
    assert_ne!(original, files(dir.path()));
    std::fs::remove_file(&lock).unwrap();
    std::fs::remove_dir(&locks).unwrap();
    std::fs::write(&locks, b"").unwrap();
    assert_ne!(original, files(dir.path()));
}
