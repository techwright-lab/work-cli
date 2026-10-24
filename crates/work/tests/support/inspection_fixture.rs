//! Owned fixture SOURCE ONLY: never invoke without separate isolated CI permission.
#![allow(dead_code)]
use std::{ffi::OsStr, fs, os::unix::ffi::OsStrExt, path::{Path, PathBuf}, process::Command};

pub struct InspectionFixture {
    pub temp: tempfile::TempDir,
    pub checkout: PathBuf,
}
impl InspectionFixture {
    pub fn directory() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let checkout = temp.path().join("checkout");
        fs::create_dir(&checkout).unwrap();
        Self { temp, checkout }
    }
    pub fn linked() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repository");
        let checkout = temp.path().join("checkout");
        fs::create_dir(&repo).unwrap();
        git(&repo, &[OsStr::new("init"), OsStr::new("--initial-branch=main")]);
        fs::write(repo.join("tracked"), b"tracked\n").unwrap();
        git(&repo, &[OsStr::new("add"), OsStr::new("--"), OsStr::new("tracked")]);
        git(&repo, &[OsStr::new("commit"), OsStr::new("-m"), OsStr::new("owned fixture")]);
        git(&repo, &[OsStr::new("worktree"), OsStr::new("add"), OsStr::new("-b"),
            OsStr::new("fixture"), checkout.as_os_str()]);
        Self { temp, checkout }
    }
    pub fn raw_payloads(&self) -> Vec<Vec<u8>> {
        fs::create_dir_all(self.checkout.join("cache/empty")).unwrap();
        self.write(b".gitignore", b"cache/\n");
        let names = vec![b"cache/\xff\n\t".to_vec(), b"cache/secret".to_vec(),
            b"cache/marker".to_vec(), b"arbitrary.pyc".to_vec(), b"-leading".to_vec()];
        for name in &names { self.write(name, b"abc"); }
        names
    }
    pub fn path(&self, raw: &[u8]) -> PathBuf { self.checkout.join(OsStr::from_bytes(raw)) }
    pub fn write(&self, raw: &[u8], bytes: &[u8]) { fs::write(self.path(raw), bytes).unwrap(); }
}
fn git(cwd: &Path, args: &[&OsStr]) {
    // Fixture creation only, not the inspection process runner. No network.
    let result = Command::new("/usr/bin/git").env_clear()
        .env("PATH", "/usr/bin:/bin").env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1").env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(["-c", "user.name=Owned Fixture", "-c", "user.email=fixture@invalid",
            "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "-c", "init.templateDir="])
        .args(args).current_dir(cwd).output().unwrap();
    assert!(result.status.success(), "owned fixture Git failed");
}
