use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};
pub fn git(path: &Path, args: &[&str]) -> String {
    let o = Command::new("git")
        .current_dir(path)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8(o.stdout).unwrap().trim().into()
}
pub struct Fixture {
    pub temp: tempfile::TempDir,
    pub repo: PathBuf,
    pub root: PathBuf,
}
impl Fixture {
    pub fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        let root = temp.path().join("root");
        std::fs::create_dir(&repo).unwrap();
        std::fs::create_dir(&root).unwrap();
        git(&repo, &["init", "-b", "main"]);
        git(&repo, &["config", "user.name", "Test"]);
        git(&repo, &["config", "user.email", "test@example.invalid"]);
        git(&repo, &["commit", "--allow-empty", "-m", "initial"]);
        let f = Self { temp, repo, root };
        f.config(10, false);
        f
    }
    pub fn config(&self, quota: u64, sink: bool) {
        std::fs::write(self.temp.path().join("config.toml"), format!("store_dir = {:?}\ntrusted_registry = {:?}\nroots = [{:?}]\nrepositories = [{:?}]\n[allocation]\nrepository_limit = {quota}\nowner_limit = {quota}\nfloor_bytes = 0\nwarn_bytes = 0\n{}", self.temp.path().join("private"), self.temp.path().join("registry"), self.root, self.repo, if sink {"capture_sink = 'unsupported'\n"} else {""})).unwrap();
    }
    pub fn start(&self, op: &str, task: &str, branch: &str, extra: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_work"))
            .args([
                "start",
                "--operation",
                op,
                "--repository",
                self.repo.to_str().unwrap(),
                "--root",
                self.root.to_str().unwrap(),
                "--actor",
                "alice",
                "--task",
                task,
                "--branch",
                branch,
                "--base",
                "main",
            ])
            .args(extra)
            .env("WORK_CONFIG", self.temp.path().join("config.toml"))
            .output()
            .unwrap()
    }
    pub fn store(&self) -> work_cli::store::Store {
        work_cli::store::Store::open_registered(
            &self.temp.path().join("registry"),
            &self.temp.path().join("private"),
            std::slice::from_ref(&self.root),
        )
        .unwrap()
    }
}
