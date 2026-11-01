//! Public native CLI installation in disposable user directories, without Python/Git.
use std::{
    fs,
    os::unix::fs::symlink,
    path::PathBuf,
    process::{Command, Output},
};

struct Fixture {
    _temp: tempfile::TempDir,
    home: PathBuf,
    data: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let data = temp.path().join("data");
        fs::create_dir(&home).unwrap();
        Self {
            _temp: temp,
            home,
            data,
        }
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_work"))
            .args(args)
            .env_clear()
            .env("HOME", &self.home)
            .env("XDG_DATA_HOME", &self.data)
            .env("PATH", "/no-tools")
            .env("WORK_CONFIG", self.home.join("invalid-config.toml"))
            .output()
            .unwrap()
    }
}

#[test]
fn native_skill_installs_embedded_files_and_references_idempotently() {
    let f = Fixture::new();
    fs::write(f.home.join("invalid-config.toml"), "invalid=[").unwrap();
    let first = f.run(&["skill", "install"]);
    assert!(first.status.success(), "{first:?}");
    let report: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(report["authority_modified"], false);
    assert_eq!(report["binary_changed"], false);
    let skill = f.home.join(".agents/skills/work-cli");
    assert_eq!(
        fs::read_to_string(skill.join("SKILL.md")).unwrap(),
        include_str!("../../../skills/work-cli/SKILL.md")
    );
    assert_eq!(
        fs::read_to_string(skill.join("reference/setup.md")).unwrap(),
        include_str!("../../../skills/work-cli/reference/setup.md")
    );
    assert_eq!(
        fs::read_to_string(skill.join("reference/../../../docs/distribution.md")).unwrap(),
        include_str!("../../../docs/distribution.md")
    );
    assert!(!f.home.join(".claude").exists());
    assert!(!f.home.join(".codex").exists());
    assert!(!f.home.join(".local/state/work").exists());
    let before = fs::read_link(f.data.join("work-cli/skill-current")).unwrap();
    let again = f.run(&["skill", "install"]);
    assert!(again.status.success(), "{again:?}");
    assert_eq!(
        fs::read_link(f.data.join("work-cli/skill-current")).unwrap(),
        before
    );
    let all = f.run(&["skill", "install", "--all"]);
    assert!(all.status.success(), "{all:?}");
    for agent in [".agents", ".claude", ".codex"] {
        assert_eq!(
            fs::read_link(f.home.join(agent).join("skills/work-cli")).unwrap(),
            f.data.join("work-cli/skill-current")
        );
    }
}

#[test]
fn unset_or_empty_xdg_uses_home_data_without_external_tools() {
    for empty in [false, true] {
        let f = Fixture::new();
        let mut command = Command::new(env!("CARGO_BIN_EXE_work"));
        command
            .args(["skill", "install"])
            .env_clear()
            .env("HOME", &f.home)
            .env("PATH", "/no-tools");
        if empty {
            command.env("XDG_DATA_HOME", "");
        }
        let result = command.output().unwrap();
        assert!(result.status.success(), "{result:?}");
        assert_eq!(
            fs::read_link(f.home.join(".agents/skills/work-cli")).unwrap(),
            f.home.join(".local/share/work-cli/skill-current")
        );
        assert!(!f.data.exists());
    }
    let f = Fixture::new();
    for (home, data) in [
        (None, f.data.as_os_str()),
        (Some(std::ffi::OsStr::new("relative")), f.data.as_os_str()),
        (Some(f.home.as_os_str()), std::ffi::OsStr::new("relative")),
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_work"));
        command
            .args(["skill", "install"])
            .env_clear()
            .env("XDG_DATA_HOME", data);
        if let Some(home) = home {
            command.env("HOME", home);
        }
        let result = command.output().unwrap();
        assert!(!result.status.success(), "{result:?}");
        assert!(!f.data.exists());
        assert_eq!(fs::read_dir(&f.home).unwrap().count(), 0);
    }
}

#[test]
fn help_version_and_parse_errors_never_install_skills() {
    let f = Fixture::new();
    for args in [
        vec!["--version"],
        vec!["--help"],
        vec!["skill", "--help"],
        vec!["skill", "install", "--help"],
    ] {
        let output = f.run(&args);
        assert!(output.status.success(), "{args:?}: {output:?}");
        assert_eq!(fs::read_dir(&f.home).unwrap().count(), 0);
        assert!(!f.data.exists());
    }
    assert!(!f.run(&["skill", "install", "--force"]).status.success());
    assert!(!f.data.exists());
}

#[test]
fn foreign_targets_and_symlinked_directories_are_preserved() {
    for case in ["foreign-skill", "symlink-parent", "authority-root"] {
        let f = Fixture::new();
        let foreign = f.home.join(".claude/skills/work-cli");
        let outside = f.home.join("outside");
        match case {
            "foreign-skill" => {
                fs::create_dir_all(&foreign).unwrap();
                fs::write(foreign.join("SKILL.md"), "keep this skill").unwrap();
            }
            "symlink-parent" => {
                fs::create_dir(&outside).unwrap();
                symlink(&outside, f.home.join(".agents")).unwrap();
            }
            "authority-root" => {
                fs::create_dir_all(f.data.join("work-cli")).unwrap();
                fs::write(f.data.join("work-cli/store.sqlite"), "retain authority").unwrap();
            }
            _ => unreachable!(),
        }
        let result = f.run(&["skill", "install", "--all"]);
        assert!(!result.status.success(), "{case}: {result:?}");
        assert!(!f.home.join(".agents/skills/work-cli").exists());
        if case == "foreign-skill" {
            assert_eq!(
                fs::read_to_string(foreign.join("SKILL.md")).unwrap(),
                "keep this skill"
            );
        }
        if case == "symlink-parent" {
            assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
        }
        if case == "authority-root" {
            assert_eq!(fs::read_dir(f.data.join("work-cli")).unwrap().count(), 1);
        }
    }
}

#[test]
fn existing_helper_managed_links_migrate_without_deleting_previous_instructions() {
    let f = Fixture::new();
    let data = f.data.join("work-cli");
    let old = PathBuf::from("skill-snapshots")
        .join("a".repeat(64))
        .join("skills/work-cli");
    fs::create_dir_all(data.join(&old)).unwrap();
    fs::write(
        data.join(&old).join("SKILL.md"),
        "retained previous instructions",
    )
    .unwrap();
    symlink(&old, data.join("skill-current")).unwrap();
    fs::create_dir_all(f.home.join(".agents/skills")).unwrap();
    symlink(
        data.join("skill-current"),
        f.home.join(".agents/skills/work-cli"),
    )
    .unwrap();
    let result = f.run(&["skill", "install", "--all"]);
    assert!(result.status.success(), "{result:?}");
    assert_ne!(fs::read_link(data.join("skill-current")).unwrap(), old);
    assert_eq!(
        fs::read_to_string(data.join(old).join("SKILL.md")).unwrap(),
        "retained previous instructions"
    );
    assert_eq!(
        fs::read_to_string(f.home.join(".agents/skills/work-cli/SKILL.md")).unwrap(),
        include_str!("../../../skills/work-cli/SKILL.md")
    );
}

#[test]
fn unmanaged_pointer_and_linked_lock_are_not_replaced() {
    for case in ["foreign-current", "symlink-lock", "hardlink-lock"] {
        let f = Fixture::new();
        let data = f.data.join("work-cli");
        fs::create_dir_all(&data).unwrap();
        let sentinel = f.home.join("sentinel");
        fs::write(&sentinel, "keep").unwrap();
        match case {
            "foreign-current" => symlink(&sentinel, data.join("skill-current")).unwrap(),
            "symlink-lock" => symlink(&sentinel, data.join(".install.lock")).unwrap(),
            "hardlink-lock" => fs::hard_link(&sentinel, data.join(".install.lock")).unwrap(),
            _ => unreachable!(),
        }
        let result = f.run(&["skill", "install"]);
        assert!(!result.status.success(), "{case}: {result:?}");
        assert_eq!(fs::read_to_string(&sentinel).unwrap(), "keep");
        assert!(!f.home.join(".agents").exists());
    }
}

#[test]
fn modified_snapshot_and_busy_installer_lock_refuse_without_replacing_links() {
    let f = Fixture::new();
    let result = f.run(&["skill", "install"]);
    assert!(result.status.success(), "{result:?}");
    let current = f.data.join("work-cli/skill-current");
    let before = fs::read_link(&current).unwrap();
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(f.data.join("work-cli/.install.lock"))
        .unwrap();
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
    let busy = f.run(&["skill", "install", "--all"]);
    assert!(!busy.status.success());
    assert_eq!(fs::read_link(&current).unwrap(), before);
    drop(lock);
    fs::write(current.join("SKILL.md"), "modified instructions").unwrap();
    let tampered = f.run(&["skill", "install"]);
    assert!(!tampered.status.success());
    assert_eq!(
        fs::read_to_string(current.join("SKILL.md")).unwrap(),
        "modified instructions"
    );
    assert_eq!(fs::read_link(&current).unwrap(), before);
}
