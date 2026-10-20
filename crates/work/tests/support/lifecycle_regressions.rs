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
pub fn files(dir: &std::path::Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    let mut result = Vec::new();
    for sub in [".work-authorities", "private"] {
        for entry in std::fs::read_dir(dir.join(sub)).unwrap() {
            let path = entry.unwrap().path();
            // SHM contains SQLite's normal reader lock bookkeeping.
            let bytes = if path.to_string_lossy().ends_with("-shm") {
                Vec::new()
            } else {
                std::fs::read(&path).unwrap()
            };
            result.push((path, bytes));
        }
    }
    result.sort();
    result
}
