use super::*;
use std::{fs, path::PathBuf};

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

    fn snapshot_exists(&self) -> bool {
        let snapshots = self.data.join("work-cli/skill-snapshots");
        snapshots.is_dir()
            && fs::read_dir(&snapshots)
                .map(|entries| {
                    entries.filter_map(|entry| entry.ok()).any(|entry| {
                        entry
                            .file_name()
                            .to_str()
                            .is_some_and(|name| name.len() == 64 && !name.starts_with('.'))
                    })
                })
                .unwrap_or(false)
    }
}

fn completed(progress: &InstallProgress, kind: InstallActionKind) -> bool {
    progress
        .actions()
        .iter()
        .any(|action| action.kind() == kind && action.status() == InstallActionStatus::Completed)
}

fn statuses(progress: &InstallProgress, kind: InstallActionKind) -> Vec<InstallActionStatus> {
    progress
        .actions()
        .iter()
        .filter(|action| action.kind() == kind)
        .map(InstallAction::status)
        .collect()
}

fn completed_directories(progress: &InstallProgress) -> Vec<PathBuf> {
    progress
        .actions()
        .iter()
        .filter(|action| {
            action.kind() == InstallActionKind::Directory
                && action.status() == InstallActionStatus::Completed
        })
        .map(|action| action.target().to_path_buf())
        .collect()
}

#[test]
fn successful_install_records_directory_snapshot_pointer_and_registration_in_order() {
    let f = Fixture::new();
    assert!(!f.data.exists());
    let (report, progress) = observe_install(false, &f.home, &f.data).expect("install");
    let kinds: Vec<_> = progress.actions().iter().map(InstallAction::kind).collect();
    let directory = kinds
        .iter()
        .position(|kind| *kind == InstallActionKind::Directory);
    let snapshot = kinds
        .iter()
        .position(|kind| *kind == InstallActionKind::Snapshot);
    let pointer = kinds
        .iter()
        .position(|kind| *kind == InstallActionKind::Pointer);
    let registration = kinds
        .iter()
        .position(|kind| *kind == InstallActionKind::Registration);
    assert!(
        directory.is_some() && snapshot.is_some() && pointer.is_some() && registration.is_some(),
        "missing progress observation: {kinds:?}"
    );
    assert!(
        directory < snapshot && snapshot < pointer && pointer < registration,
        "actions out of order: {kinds:?}"
    );
    assert!(
        progress
            .actions()
            .iter()
            .all(|action| action.status() == InstallActionStatus::Completed),
        "{progress:?}"
    );
    let created_dirs = completed_directories(&progress);
    let data_root = f.data.join("work-cli");
    assert!(
        created_dirs.contains(&f.data),
        "missing progress observation for created data parent: {created_dirs:?}"
    );
    assert!(
        created_dirs.contains(&data_root),
        "missing progress observation for created data directory: {created_dirs:?}"
    );
    assert!(progress.actions().iter().any(|action| {
        action.kind() == InstallActionKind::Registration
            && action.target() == f.home.join(".agents/skills/work-cli")
    }));
    assert!(progress.actions().iter().any(|action| {
        action.kind() == InstallActionKind::Pointer
            && action.target() == f.data.join("work-cli/skill-current")
    }));
    assert_eq!(report.skill, "work-cli");
    assert!(f.snapshot_exists());
}

#[test]
fn pre_publication_snapshot_file_failure_records_exactly_one_failed_snapshot_and_retains_directory_progress(
) {
    let f = Fixture::new();
    let result = observe_install_failing(false, &f.home, &f.data, Fault::SnapshotFileWrite);
    assert!(
        result.is_err(),
        "missing progress observation: injected snapshot file-write failure",
    );
    let err = result.err().unwrap();
    assert!(
        completed(err.progress(), InstallActionKind::Directory),
        "missing prior directory progress: {err:?}",
    );
    assert_eq!(
        statuses(err.progress(), InstallActionKind::Snapshot),
        vec![InstallActionStatus::Failed],
        "pre-publication snapshot failure must record exactly one Failed action: {err:?}",
    );
    assert!(
        !completed(err.progress(), InstallActionKind::Pointer),
        "{err:?}"
    );
    assert!(
        !completed(err.progress(), InstallActionKind::Registration),
        "{err:?}"
    );
    assert!(!f.snapshot_exists());
    assert!(!f.data.join("work-cli/skill-current").exists());
}

#[test]
fn failure_after_pointer_publication_retains_prior_actions_as_unknown_not_rollback() {
    let f = Fixture::new();
    let result = observe_install_failing(false, &f.home, &f.data, Fault::AfterPointerUncertain);
    assert!(
        result.is_err(),
        "missing progress observation: injected pointer failure"
    );
    let err = result.err().unwrap();
    assert!(
        completed(err.progress(), InstallActionKind::Directory),
        "{err:?}"
    );
    assert!(
        completed(err.progress(), InstallActionKind::Snapshot),
        "{err:?}"
    );
    assert_eq!(
        statuses(err.progress(), InstallActionKind::Pointer),
        vec![InstallActionStatus::Unknown],
        "uncertain pointer must not be skipped or rolled back: {err:?}"
    );
    assert!(
        !completed(err.progress(), InstallActionKind::Registration),
        "{err:?}"
    );
    assert!(f.snapshot_exists());
    assert!(f.data.join("work-cli/skill-current").exists());
    assert!(!f.home.join(".agents/skills/work-cli").exists());
}

#[test]
fn failure_after_earlier_registration_keeps_completed_actions_distinct_from_uncertain() {
    let f = Fixture::new();
    let result = observe_install_failing(true, &f.home, &f.data, Fault::AfterFirstRegistration);
    assert!(
        result.is_err(),
        "missing progress observation: injected registration failure"
    );
    let err = result.err().unwrap();
    assert!(
        completed(err.progress(), InstallActionKind::Directory),
        "{err:?}"
    );
    assert!(
        completed(err.progress(), InstallActionKind::Snapshot),
        "{err:?}"
    );
    assert!(
        completed(err.progress(), InstallActionKind::Pointer),
        "{err:?}"
    );
    let registrations = statuses(err.progress(), InstallActionKind::Registration);
    assert!(
        registrations.contains(&InstallActionStatus::Completed),
        "{err:?}"
    );
    assert!(
        registrations.contains(&InstallActionStatus::Failed),
        "{err:?}"
    );
    assert_ne!(InstallActionStatus::Failed, InstallActionStatus::Unknown);
    assert!(
        !registrations.contains(&InstallActionStatus::Unknown),
        "failed registration must not be recorded as unknown: {err:?}"
    );
    assert!(f.snapshot_exists());
    assert!(f.data.join("work-cli/skill-current").exists());
    assert!(f.home.join(".agents/skills/work-cli").exists());
}

#[test]
fn preflight_failure_retains_directory_progress_without_activation() {
    let f = Fixture::new();
    let foreign = f.home.join(".claude/skills/work-cli");
    fs::create_dir_all(&foreign).unwrap();
    fs::write(foreign.join("SKILL.md"), "keep this skill").unwrap();
    let result = observe_install(true, &f.home, &f.data);
    assert!(result.is_err(), "preflight foreign target must fail");
    let err = result.err().unwrap();
    assert!(
        completed(err.progress(), InstallActionKind::Directory),
        "missing progress observation: {err:?}"
    );
    assert!(
        !completed(err.progress(), InstallActionKind::Snapshot),
        "{err:?}"
    );
    assert!(
        !completed(err.progress(), InstallActionKind::Pointer),
        "{err:?}"
    );
    assert!(
        !completed(err.progress(), InstallActionKind::Registration),
        "{err:?}"
    );
    assert_eq!(
        fs::read_to_string(foreign.join("SKILL.md")).unwrap(),
        "keep this skill"
    );
    assert!(!f.home.join(".agents/skills/work-cli").exists());
    assert!(!f.data.join("work-cli/skill-current").exists());
}

#[test]
fn partial_recursive_directory_creation_retains_created_components_on_later_failure() {
    let f = Fixture::new();
    let created = f.home.join("created-component");
    assert!(!created.exists());
    let data_home = created.join("..").join("noncanonical-data");
    let result = observe_install(false, &f.home, &data_home);
    assert!(result.is_err(), "noncanonical data path must fail");
    let err = result.err().unwrap();
    let created_dirs = completed_directories(err.progress());
    assert!(
        created_dirs.contains(&created),
        "missing progress observation for created intermediate: {err:?}"
    );
    assert!(
        created.is_dir(),
        "created intermediate must persist: {created:?}"
    );
    assert!(
        !created_dirs.contains(&f.home),
        "already-existing home must not be recorded as created: {err:?}"
    );
    assert!(
        !completed(err.progress(), InstallActionKind::Snapshot),
        "{err:?}"
    );
}

#[test]
fn already_existing_directories_are_not_recorded_as_created() {
    let f = Fixture::new();
    let data_root = f.data.join("work-cli");
    let agents = f.home.join(".agents/skills");
    fs::create_dir_all(&data_root).unwrap();
    fs::create_dir_all(&agents).unwrap();
    let (_report, progress) = observe_install(false, &f.home, &f.data).expect("install");
    let created_dirs = completed_directories(&progress);
    assert!(
        !created_dirs.contains(&data_root),
        "existing data directory must not be recorded as created: {created_dirs:?}"
    );
    assert!(
        !created_dirs.contains(&agents),
        "existing discovery directory must not be recorded as created: {created_dirs:?}"
    );
    assert!(
        !created_dirs.contains(&f.home),
        "existing home must not be recorded as created: {created_dirs:?}"
    );
    let snapshots = data_root.join("skill-snapshots");
    assert!(
        created_dirs.contains(&snapshots),
        "missing progress observation for newly created snapshots directory: {created_dirs:?}"
    );
}
