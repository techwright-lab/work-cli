//! Owned fixture SOURCE ONLY: never invoke without separate isolated CI permission.
#![allow(dead_code)]
use super::work_cli_api as work_cli;
use std::{
    ffi::OsStr,
    fs,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    process::Command,
};

pub struct InspectionFixture {
    pub temp: tempfile::TempDir,
    pub checkout: PathBuf,
}
pub struct ManagedFixture {
    pub temp: tempfile::TempDir,
    pub repo: PathBuf,
    pub root: PathBuf,
    pub allocation: work_cli::allocate::Allocation,
    pub store: work_cli::store::Store,
}
impl ManagedFixture {
    pub fn new(format: &str, version: &str) -> Self {
        Self::create(tempfile::tempdir().unwrap(), format, version)
    }
    /// Recovery-preparation fixtures prefer the workspace target filesystem so
    /// tmpfs `/tmp` cannot be mistaken for persistent success.
    pub fn recovery(format: &str, version: &str) -> Self {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/recovery-fixtures");
        fs::create_dir_all(&base).unwrap();
        let base = fs::canonicalize(&base).expect("owned recovery fixture base");
        let temp = tempfile::Builder::new()
            .prefix("work-recovery-")
            .tempdir_in(&base)
            .unwrap();
        Self::create(temp, format, version)
    }
    fn create(temp: tempfile::TempDir, format: &str, version: &str) -> Self {
        let repo = temp.path().join("repository");
        let root = temp.path().join("managed");
        fs::create_dir(&repo).unwrap();
        fs::create_dir(&root).unwrap();
        git(
            &repo,
            &[
                "init".as_ref(),
                "--initial-branch=main".as_ref(),
                format!("--object-format={format}").as_ref(),
            ],
        );
        fs::write(repo.join("tracked"), b"tracked\n").unwrap();
        fs::write(repo.join(".gitignore"), b"cache/\n").unwrap();
        git(&repo, &["add".as_ref(), ".".as_ref()]);
        git(
            &repo,
            &[
                "commit".as_ref(),
                "-m".as_ref(),
                "owned inspection fixture".as_ref(),
            ],
        );
        let config = work_cli::config::Config {
            store_dir: Some(temp.path().join("authority")),
            trusted_registry: Some(temp.path().join("registry")),
            repositories: vec![repo.clone()],
            roots: vec![root.clone()],
            allocation: Some(work_cli::config::AllocationPolicy {
                repository_limit: 10,
                owner_limit: 10,
                floor_bytes: 0,
                warn_bytes: 0,
                capture_sink: None,
            }),
            ..Default::default()
        };
        let allocation = work_cli::allocate::start(
            &config,
            work_cli::allocate::Start {
                operation: uuid::Uuid::now_v7(),
                repository: Some(repo.clone()),
                root: Some(root.clone()),
                actor: Some("fixture".into()),
                owner: None,
                task: "inspection".into(),
                branch: Some("inspection".into()),
                base: "HEAD".into(),
                reuse_branch: false,
            },
        )
        .unwrap();
        if version == "3" {
            // An extended flag forces native v3 rather than relying on Git's
            // willingness to retain v3 for entries expressible as v2.
            git(
                &allocation.destination,
                &[
                    "update-index".as_ref(),
                    "--skip-worktree".as_ref(),
                    "tracked".as_ref(),
                ],
            );
        }
        git(
            &allocation.destination,
            &[
                "update-index".as_ref(),
                format!("--index-version={version}").as_ref(),
            ],
        );
        let store = work_cli::store::Store::open_existing_registered_mut(
            config.trusted_registry.as_ref().unwrap(),
            config.store_dir.as_ref().unwrap(),
            &config.roots,
        )
        .unwrap();
        Self {
            temp,
            repo,
            root,
            allocation,
            store,
        }
    }
    /// Approval-only owned setup: public adoption plus an actually populated local bare remote.
    pub fn approval(&self) -> (PathBuf, work_cli::adopted::AdoptedRequest) {
        let remote = self.temp.path().join("approval-backup.git");
        git(
            self.temp.path(),
            &[
                "init".as_ref(),
                "--bare".as_ref(),
                "--template=".as_ref(),
                remote.as_os_str(),
            ],
        );
        let url = format!("file://{}", remote.display());
        self.git(&[
            "remote".as_ref(),
            "add".as_ref(),
            "backup".as_ref(),
            url.as_ref(),
        ]);
        self.git(&[
            "-c".as_ref(),
            "protocol.file.allow=always".as_ref(),
            "push".as_ref(),
            "backup".as_ref(),
            "HEAD:refs/heads/preserved".as_ref(),
        ]);
        let config = work_cli::config::Config {
            store_dir: Some(self.temp.path().join("authority")),
            trusted_registry: Some(self.temp.path().join("registry")),
            roots: vec![self.root.clone()],
            ..Default::default()
        };
        let request: work_cli::adopted::AdoptedRequest = serde_json::from_value(serde_json::json!({
            "operation": uuid::Uuid::now_v7(), "identity": {
                "checkout": self.allocation.checkout, "group": uuid::Uuid::now_v7(),
                "run": uuid::Uuid::now_v7(), "run_ref": "approval-root", "actor": "fixture",
                "parent_run_ref": null, "execution_chain": [{"kind":"executor", "system":"test"}]
            }, "source":"approval-fixture", "session":"root-session", "agent":null
        })).unwrap();
        work_cli::adopted::begin(&config, &request).unwrap();
        let path = self.temp.path().join("approval.toml");
        fs::write(&path, format!("store_dir={:?}\ntrusted_registry={:?}\nroots=[{:?}]\n[approval]\nformat=1\nversion='fixture-v1'\noperator_id='explicit-operator'\nquiet_window_seconds=1\nexpiry_seconds=60\n[remote_preservation]\nformat=1\nversion='fixture-v1'\n[[remote_preservation.targets]]\ncommon_dir={:?}\nremote='backup'\nurl={url:?}\nbranch='refs/heads/preserved'\n[capture]\nexecutable=false\n", config.store_dir.unwrap(), config.trusted_registry.unwrap(), self.root, self.common())).unwrap();
        (path, request)
    }
    pub fn activity(
        request: &work_cli::adopted::AdoptedRequest,
    ) -> work_cli::participants::Activity {
        serde_json::from_value(serde_json::json!({
            "run":request.identity.run, "group":request.identity.group, "source":request.source,
            "participant":{"session":request.session, "agent":request.agent},
            "parent":null,"actor":null,"prompt":null,"tool":null,"event_ref":"stop-1",
            "kind":"stop","observed_at":100
        }))
        .unwrap()
    }
    pub fn path(&self, raw: &[u8]) -> PathBuf {
        self.allocation.destination.join(OsStr::from_bytes(raw))
    }
    pub fn private(&self) -> &Path {
        &self.allocation.identity.as_ref().unwrap().private_git_dir
    }
    pub fn common(&self) -> &Path {
        &self.allocation.identity.as_ref().unwrap().common_git_dir
    }
    pub fn inspect(
        &mut self,
        policies: &work_cli::disposal::ValidatedPolicies,
    ) -> work_cli::inspection::Observation {
        work_cli::inspection::inspect(&mut self.store, self.allocation.checkout, policies).unwrap()
    }
    pub fn git(&self, args: &[&OsStr]) {
        git(&self.allocation.destination, args);
    }
    pub fn sibling(&self) -> PathBuf {
        let sibling = self.temp.path().join("sibling");
        git(
            &self.repo,
            &[
                "worktree".as_ref(),
                "add".as_ref(),
                "-b".as_ref(),
                "sibling".as_ref(),
                sibling.as_os_str(),
            ],
        );
        sibling
    }
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
        git(
            &repo,
            &[OsStr::new("init"), OsStr::new("--initial-branch=main")],
        );
        fs::write(repo.join("tracked"), b"tracked\n").unwrap();
        git(
            &repo,
            &[OsStr::new("add"), OsStr::new("--"), OsStr::new("tracked")],
        );
        git(
            &repo,
            &[
                OsStr::new("commit"),
                OsStr::new("-m"),
                OsStr::new("owned fixture"),
            ],
        );
        git(
            &repo,
            &[
                OsStr::new("worktree"),
                OsStr::new("add"),
                OsStr::new("-b"),
                OsStr::new("fixture"),
                checkout.as_os_str(),
            ],
        );
        Self { temp, checkout }
    }
    pub fn raw_payloads(&self) -> Vec<Vec<u8>> {
        fs::create_dir_all(self.checkout.join("cache/empty")).unwrap();
        self.write(b".gitignore", b"cache/\n");
        let names = vec![
            b"cache/\xff\n\t".to_vec(),
            b"cache/secret".to_vec(),
            b"cache/marker".to_vec(),
            b"arbitrary.pyc".to_vec(),
            b"-leading".to_vec(),
        ];
        for name in &names {
            self.write(name, b"abc");
        }
        names
    }
    pub fn path(&self, raw: &[u8]) -> PathBuf {
        self.checkout.join(OsStr::from_bytes(raw))
    }
    pub fn write(&self, raw: &[u8], bytes: &[u8]) {
        fs::write(self.path(raw), bytes).unwrap();
    }
}
pub fn git(cwd: &Path, args: &[&OsStr]) {
    // Fixture creation only, not the inspection process runner. No network.
    let result = Command::new("/usr/bin/git")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args([
            "-c",
            "user.name=Owned Fixture",
            "-c",
            "user.email=fixture@invalid",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.templateDir=",
        ])
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap();
    assert!(result.status.success(), "owned fixture Git failed");
}
