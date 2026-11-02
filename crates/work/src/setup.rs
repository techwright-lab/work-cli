//! Consent-gated native setup. Never initializes or mutates Work authority.
use crate::{
    config::{validate_path, AllocationPolicy, Config, ConfigDocument, InstallDocument},
    skill_install::{InstallActionKind, InstallActionStatus},
};
use clap::{Args, ValueEnum};
use serde::Serialize;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufRead, IsTerminal, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
    process::Command,
    time::Duration,
};

const DEFAULT_REPOSITORY_LIMIT: u64 = 8;
const DEFAULT_OWNER_LIMIT: u64 = 4;
const DEFAULT_FLOOR_BYTES: u64 = 1_073_741_824;
const DEFAULT_WARN_BYTES: u64 = 5_368_709_120;
const AFFIRM: &str = "yes";
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const GIT: &str = "/usr/bin/git";
const LOCK_NAME: &str = ".work-setup.lock";
const BACKUP_DIR_NAME: &str = ".work-setup-backups";
const STAGE_PREFIX: &str = ".work-setup-stage-";

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum SkillsArg {
    None,
    Standard,
    All,
}

#[derive(Debug, Args)]
pub(crate) struct SetupArgs {
    /// Accountable actor; required for headless creation
    #[arg(long)]
    actor: Option<String>,
    /// Existing local non-bare Git repository (repeatable)
    #[arg(long = "repository", value_name = "PATH")]
    repository: Vec<PathBuf>,
    /// Managed root path, or an existing registered root for guidance
    #[arg(long)]
    root: Option<PathBuf>,
    /// Absolute store directory endpoint (not created by setup)
    #[arg(long)]
    store_dir: Option<PathBuf>,
    /// Absolute registry directory endpoint (not created by setup)
    #[arg(long)]
    trusted_registry: Option<PathBuf>,
    /// Allocation repository limit
    #[arg(long)]
    repository_limit: Option<u64>,
    /// Allocation owner limit
    #[arg(long)]
    owner_limit: Option<u64>,
    /// Allocation floor in bytes
    #[arg(long)]
    floor_bytes: Option<u64>,
    /// Allocation warning threshold in bytes
    #[arg(long)]
    warn_bytes: Option<u64>,
    /// Skill registration: none, standard, or all
    #[arg(long, value_enum)]
    skills: Option<SkillsArg>,
    /// Confirm the validated proposal without prompting
    #[arg(long)]
    yes: bool,
    /// Use line prompts even when stdin is not a terminal
    #[arg(long)]
    interactive: bool,
    /// Validate and preview without mutation or skill registration
    #[arg(long)]
    dry_run: bool,
    /// Inspect selected configuration and prerequisites only
    #[arg(long)]
    check: bool,
    /// Canonical repository to append to existing configuration (repeatable)
    #[arg(long = "add-repository", value_name = "PATH")]
    add_repository: Vec<PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SetupAction {
    Inspect,
    Create,
    AddRepositories,
    SkillsOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SetupOutcome {
    Success,
    NoOp,
    Preview,
    Cancelled,
    Failed,
    Partial,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SkillsSelection {
    None,
    Standard,
    All,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SkillsStatus {
    Skipped,
    Succeeded,
    Failed,
    Unknown,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct SkillActionReport {
    kind: String,
    target: String,
    status: String,
}

#[derive(Clone, Debug, Serialize)]
struct SkillsReport {
    selection: SkillsSelection,
    status: SkillsStatus,
    actions: Vec<SkillActionReport>,
}

#[derive(Clone, Debug, Serialize)]
struct ReportError {
    field: Option<String>,
    location: Option<String>,
    reason: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct SetupReport {
    pub(crate) config_path: Option<String>,
    pub(crate) action: SetupAction,
    pub(crate) outcome: SetupOutcome,
    pub(crate) config_written: bool,
    pub(crate) authority_modified: bool,
    pub(crate) created_directories: Vec<String>,
    pub(crate) backup_path: Option<String>,
    skills: SkillsReport,
    pub(crate) next_steps: Vec<Vec<String>>,
    error: Option<ReportError>,
}

#[derive(Clone, Debug)]
pub(crate) struct SetupPlan {
    pub(crate) action: SetupAction,
    pub(crate) config_path: PathBuf,
    rendered: Option<String>,
    original: Option<OriginalFile>,
    create_directories: Vec<PathBuf>,
    skills: SkillsSelection,
    actor: Option<String>,
    repositories: Vec<PathBuf>,
    roots: Vec<PathBuf>,
    store_dir: Option<PathBuf>,
    trusted_registry: Option<PathBuf>,
    repository_limit: Option<u64>,
    owner_limit: Option<u64>,
    floor_bytes: Option<u64>,
    warn_bytes: Option<u64>,
    guidance_root: Option<PathBuf>,
}

#[derive(Clone, Debug)]
struct OriginalFile {
    bytes: Vec<u8>,
    dev: u64,
    ino: u64,
    len: u64,
}

#[derive(Debug)]
struct Fail {
    action: SetupAction,
    field: Option<&'static str>,
    location: Option<PathBuf>,
    reason: String,
    config_written: bool,
}

enum Class {
    Missing,
    Existing,
    Unusable(&'static str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WriterStep {
    CreateDir,
    StageCreate,
    StageWrite,
    StageFlush,
    StageSync,
    BackupCreate,
    BackupWrite,
    BackupSync,
    BackupDirSync,
    RenameNoreplace,
    RenameReplace,
    ParentSync,
    OpenLock,
    Flock,
    Unlock,
}

pub(crate) fn command(args: SetupArgs) {
    let report = execute(args);
    println!(
        "{}",
        serde_json::to_string(&report).expect("setup report serialization")
    );
    if !successful(&report) {
        std::process::exit(1);
    }
}

pub(crate) fn execute(args: SetupArgs) -> SetupReport {
    execute_io(args, &mut io::stdin().lock(), &mut io::stderr())
}

fn execute_io(args: SetupArgs, stdin: &mut dyn BufRead, stderr: &mut dyn Write) -> SetupReport {
    if let Some(report) = flag_error(&args) {
        return report;
    }
    let Some(path) = Config::discover_path() else {
        return fail(
            SetupAction::Inspect,
            None,
            Some("config_path"),
            None,
            "configuration discovery is disabled or no usable HOME/XDG selector is available",
        );
    };
    run_with_path(args, path, stdin, stderr)
}

fn run_with_path(
    args: SetupArgs,
    path: PathBuf,
    stdin: &mut dyn BufRead,
    stderr: &mut dyn Write,
) -> SetupReport {
    let prompting = should_prompt(&args);
    if args.check {
        return check_mode(&path, prompting, stderr);
    }
    match classify(&path) {
        Class::Unusable(reason) => fail(
            SetupAction::Inspect,
            Some(&path),
            Some("config_path"),
            Some(&path),
            reason,
        ),
        Class::Missing => create_flow(args, path, prompting, stdin, stderr),
        Class::Existing => existing_flow(args, path, prompting, stdin, stderr),
    }
}

fn should_prompt(args: &SetupArgs) -> bool {
    args.interactive || (io::stdin().is_terminal() && !args.yes)
}

fn successful(report: &SetupReport) -> bool {
    matches!(
        report.outcome,
        SetupOutcome::Success | SetupOutcome::NoOp | SetupOutcome::Preview
    )
}

fn flag_error(args: &SetupArgs) -> Option<SetupReport> {
    let err = |field: &'static str, reason: &str| {
        Some(fail(SetupAction::Inspect, None, Some(field), None, reason))
    };
    if args.interactive && args.yes {
        return err(
            "interactive",
            "--interactive and --yes are mutually exclusive",
        );
    }
    if args.dry_run && args.yes {
        return err("dry_run", "--dry-run cannot be combined with --yes");
    }
    if !args.repository.is_empty() && !args.add_repository.is_empty() {
        return err(
            "repository",
            "--repository cannot be combined with --add-repository",
        );
    }
    if args.check
        && (args.actor.is_some()
            || !args.repository.is_empty()
            || args.store_dir.is_some()
            || args.trusted_registry.is_some()
            || args.repository_limit.is_some()
            || args.owner_limit.is_some()
            || args.floor_bytes.is_some()
            || args.warn_bytes.is_some()
            || !args.add_repository.is_empty()
            || args.root.is_some()
            || args.skills.is_some()
            || args.yes
            || args.dry_run)
    {
        return err(
            "check",
            "--check rejects creation, addition, root, skills, --yes and --dry-run",
        );
    }
    None
}

fn classify(path: &Path) -> Class {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Class::Missing,
        Err(_) => Class::Unusable("cannot inspect configuration path"),
        Ok(meta) if meta.file_type().is_symlink() || !meta.is_file() => {
            Class::Unusable("configuration file must be a regular file")
        }
        Ok(_) => Class::Existing,
    }
}

fn check_mode(path: &Path, prompting: bool, stderr: &mut dyn Write) -> SetupReport {
    let _ = prompting;
    let mut report = blank(SetupAction::Inspect, Some(path), SetupOutcome::Success);
    match classify(path) {
        Class::Missing => {
            report.error = Some(ReportError {
                field: Some("config_path".into()),
                location: Some(path.display().to_string()),
                reason: "configuration file is missing".into(),
            });
            let _ = writeln!(
                stderr,
                "setup check: missing configuration at {}",
                path.display()
            );
        }
        Class::Unusable(reason) => {
            report.error = Some(ReportError {
                field: Some("config_path".into()),
                location: Some(path.display().to_string()),
                reason: reason.into(),
            });
            let _ = writeln!(stderr, "setup check: {reason}");
        }
        Class::Existing => match read_original(path) {
            Ok((original, document)) => match inspect_existing(path, &document) {
                Ok(()) => {
                    let _ = writeln!(
                        stderr,
                        "setup check: configuration at {} validates",
                        path.display()
                    );
                    let _ = original;
                }
                Err(fail) => {
                    report.error = Some(ReportError {
                        field: fail.field.map(str::to_owned),
                        location: fail
                            .location
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .or_else(|| Some(path.display().to_string())),
                        reason: fail.reason,
                    });
                    let _ = writeln!(stderr, "setup check: configuration is unusable");
                }
            },
            Err(fail) => {
                report.error = Some(ReportError {
                    field: fail.field.map(str::to_owned),
                    location: Some(path.display().to_string()),
                    reason: fail.reason,
                });
                let _ = writeln!(stderr, "setup check: configuration is unusable");
            }
        },
    }
    if report.error.is_some() {
        report.outcome = SetupOutcome::Failed;
    }
    report
}

fn inspect_existing(path: &Path, document: &ConfigDocument) -> Result<(), Fail> {
    let config = document.execution().map_err(|err| {
        fail_val(
            SetupAction::Inspect,
            Some("config"),
            Some(path),
            sanitize_config_error(&err),
        )
    })?;
    match (config.store_dir.as_ref(), config.trusted_registry.as_ref()) {
        (Some(store), Some(registry)) => match endpoints_absent(store, registry) {
            Ok(true) => Ok(()),
            Ok(false) => crate::interactive::open(&config).map(|_| ()).map_err(|_| {
                fail_val(
                    SetupAction::Inspect,
                    Some("root"),
                    Some(path),
                    "unresolved or conflicting authority data",
                )
            }),
            Err(fail) => Err(fail),
        },
        _ => Ok(()),
    }
}

fn create_flow(
    args: SetupArgs,
    path: PathBuf,
    prompting: bool,
    stdin: &mut dyn BufRead,
    stderr: &mut dyn Write,
) -> SetupReport {
    if !args.add_repository.is_empty() {
        return fail(
            SetupAction::Inspect,
            Some(&path),
            Some("add_repository"),
            Some(&path),
            "--add-repository requires existing configuration",
        );
    }
    match collect_create(&args, &path, prompting, stdin, stderr) {
        Err(Collect::Cancel) => cancelled(Some(&path)),
        Err(Collect::Fail(fail)) => fail.into_report(Some(&path)),
        Ok(plan) => apply_plan(plan, &args, prompting, stdin, stderr),
    }
}

fn existing_flow(
    args: SetupArgs,
    path: PathBuf,
    prompting: bool,
    stdin: &mut dyn BufRead,
    stderr: &mut dyn Write,
) -> SetupReport {
    if let Some(reason) = protected_create_fields(&args) {
        return fail(
            SetupAction::Inspect,
            Some(&path),
            Some(reason),
            Some(&path),
            "existing configuration refuses first-time or protected-setting flags",
        );
    }
    match collect_existing(&args, &path, prompting, stdin, stderr) {
        Err(Collect::Cancel) => cancelled(Some(&path)),
        Err(Collect::Fail(fail)) => fail.into_report(Some(&path)),
        Ok(plan) => apply_plan(plan, &args, prompting, stdin, stderr),
    }
}

fn protected_create_fields(args: &SetupArgs) -> Option<&'static str> {
    if args.actor.is_some() {
        return Some("actor");
    }
    if !args.repository.is_empty() {
        return Some("repository");
    }
    if args.store_dir.is_some() {
        return Some("store_dir");
    }
    if args.trusted_registry.is_some() {
        return Some("trusted_registry");
    }
    if args.repository_limit.is_some() {
        return Some("repository_limit");
    }
    if args.owner_limit.is_some() {
        return Some("owner_limit");
    }
    if args.floor_bytes.is_some() {
        return Some("floor_bytes");
    }
    if args.warn_bytes.is_some() {
        return Some("warn_bytes");
    }
    None
}

#[derive(Debug)]
enum Collect {
    Fail(Fail),
    Cancel,
}

impl From<Fail> for Collect {
    fn from(value: Fail) -> Self {
        Self::Fail(value)
    }
}

fn collect_create(
    args: &SetupArgs,
    path: &Path,
    prompting: bool,
    stdin: &mut dyn BufRead,
    stderr: &mut dyn Write,
) -> Result<SetupPlan, Collect> {
    if !path.is_absolute() {
        return Err(fail_val(
            SetupAction::Inspect,
            Some("config_path"),
            Some(path),
            "setup writes require an absolute configuration path",
        )
        .into());
    }
    writer_ancestors(path, true).map_err(Collect::from)?;
    let actor = collect_actor(args, prompting, stdin, stderr)?;
    let repositories = collect_repositories(args, prompting, stdin, stderr)?;
    let root = collect_path_field(
        args.root.as_ref(),
        prompting,
        "Managed root",
        default_root(),
        stdin,
        stderr,
        "root",
    )?;
    let store_dir = collect_path_field(
        args.store_dir.as_ref(),
        prompting,
        "Store directory",
        default_store(),
        stdin,
        stderr,
        "store_dir",
    )?;
    let trusted_registry = collect_path_field(
        args.trusted_registry.as_ref(),
        prompting,
        "Trusted registry",
        default_registry(),
        stdin,
        stderr,
        "trusted_registry",
    )?;
    let repository_limit = collect_u64(
        args.repository_limit,
        prompting,
        "Repository limit",
        DEFAULT_REPOSITORY_LIMIT,
        stdin,
        stderr,
        "repository_limit",
    )?;
    let owner_limit = collect_u64(
        args.owner_limit,
        prompting,
        "Owner limit",
        DEFAULT_OWNER_LIMIT,
        stdin,
        stderr,
        "owner_limit",
    )?;
    let floor_bytes = collect_u64(
        args.floor_bytes,
        prompting,
        "Floor bytes",
        DEFAULT_FLOOR_BYTES,
        stdin,
        stderr,
        "floor_bytes",
    )?;
    let warn_bytes = collect_u64(
        args.warn_bytes,
        prompting,
        "Warning bytes",
        DEFAULT_WARN_BYTES,
        stdin,
        stderr,
        "warn_bytes",
    )?;
    let skills = collect_skills(args, prompting, stdin, stderr)?;
    if warn_bytes < floor_bytes {
        return Err(fail_val(
            SetupAction::Create,
            Some("warn_bytes"),
            Some(path),
            "warn_bytes below floor_bytes",
        )
        .into());
    }
    let root = writer_path(&root, false, "root")?;
    let store_dir = writer_path(&store_dir, false, "store_dir")?;
    let trusted_registry = writer_path(&trusted_registry, false, "trusted_registry")?;
    let repositories = validate_repositories(&repositories, std::slice::from_ref(&root))?;
    validate_overlaps(
        path,
        &store_dir,
        &trusted_registry,
        &repositories,
        std::slice::from_ref(&root),
    )?;
    endpoint_absent(&store_dir, "store_dir")?;
    endpoint_absent(&trusted_registry, "trusted_registry")?;
    let allocation = AllocationPolicy {
        repository_limit,
        owner_limit,
        floor_bytes,
        warn_bytes,
        capture_sink: None,
    };
    let document = ConfigDocument::from_install(InstallDocument {
        actor: actor.clone(),
        repositories: repositories.clone(),
        roots: vec![root.clone()],
        store_dir: store_dir.clone(),
        trusted_registry: trusted_registry.clone(),
        allocation,
    })
    .map_err(|err| {
        fail_val(
            SetupAction::Create,
            Some("config"),
            Some(path),
            sanitize_config_error(&err),
        )
    })?;
    let rendered = document.render().map_err(|err| {
        fail_val(
            SetupAction::Create,
            Some("config"),
            Some(path),
            sanitize_config_error(&err),
        )
    })?;
    let create_directories = planned_directories(path, &root, &store_dir, &trusted_registry);
    Ok(SetupPlan {
        action: SetupAction::Create,
        config_path: path.to_path_buf(),
        rendered: Some(rendered),
        original: None,
        create_directories,
        skills,
        actor: Some(actor),
        repositories,
        roots: vec![root],
        store_dir: Some(store_dir),
        trusted_registry: Some(trusted_registry),
        repository_limit: Some(repository_limit),
        owner_limit: Some(owner_limit),
        floor_bytes: Some(floor_bytes),
        warn_bytes: Some(warn_bytes),
        guidance_root: None,
    })
}

fn collect_existing(
    args: &SetupArgs,
    path: &Path,
    prompting: bool,
    stdin: &mut dyn BufRead,
    stderr: &mut dyn Write,
) -> Result<SetupPlan, Collect> {
    let (original, mut document) = read_original(path).map_err(Collect::from)?;
    let existing_repos = document.repositories().map_err(|err| {
        fail_val(
            SetupAction::Inspect,
            Some("repositories"),
            Some(path),
            sanitize_config_error(&err),
        )
    })?;
    let existing_roots = document.roots().map_err(|err| {
        fail_val(
            SetupAction::Inspect,
            Some("roots"),
            Some(path),
            sanitize_config_error(&err),
        )
    })?;
    let actor = document.default_actor().map_err(|err| {
        fail_val(
            SetupAction::Inspect,
            Some("actor"),
            Some(path),
            sanitize_config_error(&err),
        )
    })?;
    let execution = document.execution().map_err(|err| {
        fail_val(
            SetupAction::Inspect,
            Some("config"),
            Some(path),
            sanitize_config_error(&err),
        )
    })?;
    let guidance_root = if let Some(root) = &args.root {
        let root = writer_path(root, true, "root")?;
        if !existing_roots.iter().any(|candidate| candidate == &root) {
            return Err(fail_val(
                SetupAction::Inspect,
                Some("root"),
                Some(path),
                "root must be an existing registered root",
            )
            .into());
        }
        Some(root)
    } else {
        None
    };
    if guidance_root.is_some() {
        require_registered(&execution, path)?;
    }
    let allocation = document.allocation().ok().flatten();
    let finish = |action: SetupAction,
                  rendered: Option<String>,
                  original: OriginalFile,
                  skills: SkillsSelection,
                  actor: Option<String>,
                  repositories: Vec<PathBuf>| {
        SetupPlan {
            action,
            config_path: path.to_path_buf(),
            rendered,
            original: Some(original),
            create_directories: Vec::new(),
            skills,
            actor,
            repositories,
            roots: existing_roots.clone(),
            store_dir: execution.store_dir.clone(),
            trusted_registry: execution.trusted_registry.clone(),
            repository_limit: allocation.as_ref().map(|a| a.repository_limit),
            owner_limit: allocation.as_ref().map(|a| a.owner_limit),
            floor_bytes: allocation.as_ref().map(|a| a.floor_bytes),
            warn_bytes: allocation.as_ref().map(|a| a.warn_bytes),
            guidance_root: guidance_root.clone(),
        }
    };
    let _ = writeln!(stderr, "Existing configuration: {}", path.display());
    if let Some(actor) = &actor {
        let _ = writeln!(stderr, "actor: {actor}");
    }
    if prompting {
        inspect_existing(path, &document)?;
    }
    let mut additions = args.add_repository.clone();
    if prompting && args.add_repository.is_empty() && args.repository.is_empty() {
        loop {
            match prompt(
                stderr,
                stdin,
                "Additional repository (empty to finish)",
                None,
            )? {
                None => return Err(Collect::Cancel),
                Some(value) if value.is_empty() => break,
                Some(value) => additions.push(PathBuf::from(value)),
            }
        }
    }
    let skills = collect_skills(args, prompting, stdin, stderr)?;
    if additions.is_empty() && skills == SkillsSelection::None {
        if !prompting {
            inspect_existing(path, &document)?;
        }
        return Ok(finish(
            SetupAction::Inspect,
            None,
            original,
            skills,
            actor,
            existing_repos,
        ));
    }
    let roots_for_git = existing_roots.clone();
    let prospective_repos = if additions.is_empty() {
        existing_repos.clone()
    } else {
        let mut combined = existing_repos.clone();
        combined.extend(additions.iter().cloned());
        combined
    };
    if let (Some(store), Some(registry)) = (&execution.store_dir, &execution.trusted_registry) {
        if skills != SkillsSelection::None || !additions.is_empty() {
            validate_overlaps(path, store, registry, &prospective_repos, &existing_roots)?;
        }
    }
    let mut added = Vec::new();
    if !additions.is_empty() {
        let already = existing_repos
            .iter()
            .filter_map(|repo| repo.to_str().map(str::to_owned))
            .collect::<std::collections::BTreeSet<_>>();
        let mut pending = Vec::new();
        for repo in additions {
            match validate_path(&repo, true) {
                Ok(canonical)
                    if canonical
                        .to_str()
                        .is_some_and(|text| already.contains(text)) => {}
                _ => pending.push(repo),
            }
        }
        if pending.is_empty() && skills == SkillsSelection::None {
            return Ok(finish(
                SetupAction::AddRepositories,
                None,
                original,
                skills,
                actor,
                existing_repos,
            ));
        }
        if !pending.is_empty() {
            require_registered(&execution, path)?;
            validate_config_writer(path, SetupAction::AddRepositories)?;
            let validated = validate_repositories(&pending, &roots_for_git)?;
            for repo in validated {
                match document.add_repository(repo.clone()) {
                    Ok(true) => added.push(repo),
                    Ok(false) => {}
                    Err(err) => {
                        return Err(fail_val(
                            SetupAction::AddRepositories,
                            Some("add_repository"),
                            Some(path),
                            sanitize_config_error(&err),
                        )
                        .into());
                    }
                }
            }
        }
    }
    if added.is_empty() && skills == SkillsSelection::None {
        return Ok(finish(
            SetupAction::AddRepositories,
            None,
            original,
            skills,
            actor,
            existing_repos,
        ));
    }
    if added.is_empty() {
        return Ok(finish(
            SetupAction::SkillsOnly,
            None,
            original,
            skills,
            actor,
            existing_repos,
        ));
    }
    let rendered = document.render().map_err(|err| {
        fail_val(
            SetupAction::AddRepositories,
            Some("config"),
            Some(path),
            sanitize_config_error(&err),
        )
    })?;
    let repositories = document.repositories().map_err(|err| {
        fail_val(
            SetupAction::AddRepositories,
            Some("repositories"),
            Some(path),
            sanitize_config_error(&err),
        )
    })?;
    Ok(finish(
        SetupAction::AddRepositories,
        Some(rendered),
        original,
        skills,
        actor,
        repositories,
    ))
}

fn require_registered(config: &Config, path: &Path) -> Result<(), Fail> {
    match (config.store_dir.as_ref(), config.trusted_registry.as_ref()) {
        (Some(store), Some(registry)) => match endpoints_absent(store, registry) {
            Ok(true) => {
                return Err(fail_val(
                        SetupAction::AddRepositories,
                        Some("root"),
                        Some(path),
                        "repository addition requires registered-root evidence; start the authority first",
                    ));
            }
            Ok(false) => {}
            Err(fail) => return Err(fail),
        },
        _ => {
            return Err(fail_val(
                SetupAction::AddRepositories,
                Some("config"),
                Some(path),
                "repository addition requires registered-root evidence",
            ));
        }
    }
    crate::interactive::open(config).map(|_| ()).map_err(|_| {
        fail_val(
            SetupAction::AddRepositories,
            Some("root"),
            Some(path),
            "repository addition requires registered-root evidence; unresolved or conflicting authority was not repaired",
        )
    })
}

fn apply_plan(
    plan: SetupPlan,
    args: &SetupArgs,
    prompting: bool,
    stdin: &mut dyn BufRead,
    stderr: &mut dyn Write,
) -> SetupReport {
    if let Err(err) = preview(&plan, stderr) {
        return io_fail(&plan, "preview", err);
    }
    if args.dry_run {
        let mut report = blank(plan.action, Some(&plan.config_path), SetupOutcome::Preview);
        report.skills.selection = plan.skills;
        report.next_steps = next_steps(&plan, false);
        return report;
    }
    if plan.action == SetupAction::Inspect {
        let mut report = blank(plan.action, Some(&plan.config_path), SetupOutcome::Success);
        report.next_steps = next_steps(&plan, false);
        return report;
    }
    if plan.action == SetupAction::AddRepositories && plan.rendered.is_none() {
        let mut report = blank(plan.action, Some(&plan.config_path), SetupOutcome::NoOp);
        report.skills.selection = plan.skills;
        report.next_steps = next_steps(&plan, false);
        return report;
    }
    if prompting {
        match confirm(stdin, stderr) {
            Err(Collect::Cancel) | Ok(false) => return cancelled(Some(&plan.config_path)),
            Ok(true) => {}
            Err(Collect::Fail(fail)) => return fail.into_report(Some(&plan.config_path)),
        }
    } else if !args.yes {
        return fail(
            plan.action,
            Some(&plan.config_path),
            Some("yes"),
            Some(&plan.config_path),
            "headless apply requires --yes",
        );
    }
    mutate(plan)
}

fn mutate(mut plan: SetupPlan) -> SetupReport {
    let mut created = Vec::new();
    if plan.action == SetupAction::Create {
        if let Err(err) = materialize_directories(&plan.create_directories, &mut created) {
            let mut report = err.into_report(Some(&plan.config_path));
            report.created_directories = display_dirs(&created);
            return report;
        }
        if let (Some(store), Some(registry), Some(root)) = (
            plan.store_dir.as_ref(),
            plan.trusted_registry.as_ref(),
            plan.roots.first(),
        ) {
            if let Err(err) =
                revalidate_create(&plan.config_path, root, store, registry, &plan.repositories)
            {
                let mut report = err.into_report(Some(&plan.config_path));
                report.created_directories = display_dirs(&created);
                return report;
            }
        }
    }
    let write_config = plan.rendered.is_some() && plan.action != SetupAction::SkillsOnly;
    let mut backup_path = None;
    let mut config_written = false;
    if write_config {
        match publish(&plan, &mut backup_path, &mut created) {
            Ok(()) => config_written = true,
            Err(err) => {
                let mut report = err.into_report(Some(&plan.config_path));
                report.created_directories = display_dirs(&created);
                report.backup_path = backup_path.as_ref().map(|p| p.display().to_string());
                return report;
            }
        }
        if let Err(err) = step(WriterStep::ParentSync)
            .and_then(|_| sync_path(plan.config_path.parent().unwrap_or(Path::new("/"))))
        {
            let mut report = blank(plan.action, Some(&plan.config_path), SetupOutcome::Partial);
            report.config_written = true;
            report.created_directories = display_dirs(&created);
            report.backup_path = backup_path.as_ref().map(|p| p.display().to_string());
            report.skills.selection = plan.skills;
            report.error = Some(ReportError {
                field: Some("config_path".into()),
                location: Some(plan.config_path.display().to_string()),
                reason: format!(
                    "configuration published but parent durability is uncertain ({err})"
                ),
            });
            return report;
        }
    }
    let mut report = blank(
        plan.action,
        Some(&plan.config_path),
        if plan.action == SetupAction::SkillsOnly || write_config {
            SetupOutcome::Success
        } else {
            SetupOutcome::NoOp
        },
    );
    report.config_written = config_written;
    report.created_directories = display_dirs(&created);
    report.backup_path = backup_path.as_ref().map(|p| p.display().to_string());
    report.skills.selection = plan.skills;
    if let Err(err) = install_selected(&mut plan, &mut report) {
        return err;
    }
    report.next_steps = next_steps(&plan, report.skills.status == SkillsStatus::Succeeded);
    report
}

fn revalidate_create(
    config: &Path,
    root: &Path,
    store: &Path,
    registry: &Path,
    repositories: &[PathBuf],
) -> Result<(), Fail> {
    writer_ancestors(config, true)?;
    writer_path(root, true, "root")?;
    validate_overlaps(config, store, registry, repositories, &[root.to_path_buf()])?;
    endpoint_absent(store, "store_dir")?;
    endpoint_absent(registry, "trusted_registry")?;
    Ok(())
}

#[allow(clippy::result_large_err)]
fn install_selected(plan: &mut SetupPlan, report: &mut SetupReport) -> Result<(), SetupReport> {
    report.skills.selection = plan.skills;
    match plan.skills {
        SkillsSelection::None => {
            report.skills.status = SkillsStatus::Skipped;
            Ok(())
        }
        SkillsSelection::Standard | SkillsSelection::All => {
            if report.outcome == SetupOutcome::Partial {
                report.skills.status = SkillsStatus::Skipped;
                return Ok(());
            }
            let all = plan.skills == SkillsSelection::All;
            match run_installer(all) {
                Ok(actions) => {
                    report.skills.status = SkillsStatus::Succeeded;
                    report.skills.actions = actions;
                    Ok(())
                }
                Err((actions, message)) => {
                    report.skills.actions = actions.clone();
                    report.skills.status = if actions.iter().any(|a| a.status == "unknown") {
                        SkillsStatus::Unknown
                    } else {
                        SkillsStatus::Failed
                    };
                    report.outcome = if report.config_written
                        || !report.created_directories.is_empty()
                        || report.backup_path.is_some()
                        || plan.action == SetupAction::SkillsOnly
                    {
                        SetupOutcome::Partial
                    } else {
                        SetupOutcome::Failed
                    };
                    report.error = Some(ReportError {
                        field: Some("skills".into()),
                        location: Some(plan.config_path.display().to_string()),
                        reason: sanitize_skill_error(&message),
                    });
                    report.next_steps = next_steps(plan, false);
                    Err(report.clone())
                }
            }
        }
    }
}

fn run_installer(all: bool) -> Result<Vec<SkillActionReport>, (Vec<SkillActionReport>, String)> {
    #[cfg(test)]
    if let Some(result) = take_installer_stub() {
        return result;
    }
    install_with_progress_mapped(all)
}

fn install_with_progress_mapped(
    all: bool,
) -> Result<Vec<SkillActionReport>, (Vec<SkillActionReport>, String)> {
    match crate::skill_install::install_with_progress(all) {
        Ok((_, progress)) => Ok(map_actions(progress.actions())),
        Err(err) => Err((
            map_actions(err.progress().actions()),
            err.message().to_owned(),
        )),
    }
}

fn map_actions(actions: &[crate::skill_install::InstallAction]) -> Vec<SkillActionReport> {
    actions
        .iter()
        .map(|action| SkillActionReport {
            kind: match action.kind() {
                InstallActionKind::Directory => "directory",
                InstallActionKind::Snapshot => "snapshot",
                InstallActionKind::Pointer => "pointer",
                InstallActionKind::Registration => "registration",
            }
            .into(),
            target: action.target().display().to_string(),
            status: match action.status() {
                InstallActionStatus::Completed => "completed",
                InstallActionStatus::Failed => "failed",
                InstallActionStatus::Unknown => "unknown",
            }
            .into(),
        })
        .collect()
}

fn next_steps(plan: &SetupPlan, skills_ok: bool) -> Vec<Vec<String>> {
    let mut steps = Vec::new();
    if matches!(
        plan.action,
        SetupAction::Create | SetupAction::AddRepositories
    ) || (plan.action == SetupAction::Inspect && plan.guidance_root.is_some())
    {
        if let Some(actor) = &plan.actor {
            let mut start = vec![
                "work".into(),
                "start".into(),
                "--actor".into(),
                actor.clone(),
            ];
            if plan.repositories.len() != 1 {
                if let Some(repo) = plan.repositories.first() {
                    start.push("--repository".into());
                    start.push(repo.display().to_string());
                }
            } else if plan.action == SetupAction::Create {
                start.push("--repository".into());
                start.push(plan.repositories[0].display().to_string());
            }
            let root = plan.guidance_root.as_ref().or_else(|| {
                if plan.roots.len() != 1 || plan.action == SetupAction::Create {
                    plan.roots.first()
                } else {
                    None
                }
            });
            if let Some(root) = root {
                start.push("--root".into());
                start.push(root.display().to_string());
            }
            steps.push(start);
        }
    }
    if skills_ok && plan.skills != SkillsSelection::None {
        steps.push(vec!["reload-skill-catalog".into()]);
    }
    steps
}

fn preview(plan: &SetupPlan, stderr: &mut dyn Write) -> io::Result<()> {
    writeln!(stderr, "Setup proposal")?;
    writeln!(stderr, "config: {}", plan.config_path.display())?;
    writeln!(stderr, "action: {:?}", plan.action)?;
    if let Some(actor) = &plan.actor {
        writeln!(stderr, "actor: {actor}")?;
    }
    for repo in &plan.repositories {
        writeln!(stderr, "repository: {}", repo.display())?;
    }
    for root in &plan.roots {
        writeln!(stderr, "root: {}", root.display())?;
    }
    if let Some(store) = &plan.store_dir {
        writeln!(stderr, "store_dir: {}", store.display())?;
    }
    if let Some(registry) = &plan.trusted_registry {
        writeln!(stderr, "trusted_registry: {}", registry.display())?;
    }
    if let Some(limit) = plan.repository_limit {
        writeln!(stderr, "repository_limit: {limit}")?;
    }
    if let Some(limit) = plan.owner_limit {
        writeln!(stderr, "owner_limit: {limit}")?;
    }
    if let Some(bytes) = plan.floor_bytes {
        writeln!(stderr, "floor_bytes: {bytes} {}", readable_bytes(bytes))?;
    }
    if let Some(bytes) = plan.warn_bytes {
        writeln!(stderr, "warn_bytes: {bytes} {}", readable_bytes(bytes))?;
    }
    writeln!(stderr, "skills: {:?}", plan.skills)?;
    for dir in &plan.create_directories {
        writeln!(stderr, "create directory: {}", dir.display())?;
    }
    Ok(())
}

fn confirm(stdin: &mut dyn BufRead, stderr: &mut dyn Write) -> Result<bool, Collect> {
    writeln!(
        stderr,
        "Type {AFFIRM} to apply these actions (default: no):"
    )
    .map_err(|err| {
        fail_val(
            SetupAction::Inspect,
            Some("confirmation"),
            None,
            err.to_string(),
        )
    })?;
    stderr.flush().ok();
    match read_line(stdin)? {
        None => Err(Collect::Cancel),
        Some(value) => Ok(value == AFFIRM),
    }
}

fn collect_actor(
    args: &SetupArgs,
    prompting: bool,
    stdin: &mut dyn BufRead,
    stderr: &mut dyn Write,
) -> Result<String, Collect> {
    if let Some(actor) = &args.actor {
        return valid_actor(actor);
    }
    if prompting {
        let suggested = std::env::var("USER")
            .ok()
            .filter(|user| crate::allocate::component(user));
        match prompt(stderr, stdin, "Actor", suggested.as_deref())? {
            None => Err(Collect::Cancel),
            Some(value) if value.is_empty() => match suggested {
                Some(value) => valid_actor(&value),
                None => Err(fail_val(
                    SetupAction::Create,
                    Some("actor"),
                    None,
                    "empty response cannot accept an undisplayed default",
                )
                .into()),
            },
            Some(value) => valid_actor(&value),
        }
    } else {
        Err(fail_val(
            SetupAction::Inspect,
            Some("actor"),
            None,
            "headless creation requires --actor",
        )
        .into())
    }
}

fn valid_actor(actor: &str) -> Result<String, Collect> {
    if crate::allocate::component(actor) {
        Ok(actor.to_owned())
    } else {
        Err(fail_val(SetupAction::Inspect, Some("actor"), None, "invalid actor").into())
    }
}

fn collect_repositories(
    args: &SetupArgs,
    prompting: bool,
    stdin: &mut dyn BufRead,
    stderr: &mut dyn Write,
) -> Result<Vec<PathBuf>, Collect> {
    if !args.repository.is_empty() {
        return Ok(args.repository.clone());
    }
    if !prompting {
        return Err(fail_val(
            SetupAction::Inspect,
            Some("repository"),
            None,
            "headless creation requires --repository",
        )
        .into());
    }
    let cwd_default = std::env::current_dir()
        .ok()
        .and_then(|cwd| validate_repositories(std::slice::from_ref(&cwd), &[]).ok())
        .and_then(|mut repos| repos.pop());
    let shown = cwd_default.as_ref().and_then(|path| path.to_str());
    let first = match prompt(stderr, stdin, "Repository", shown)? {
        None => return Err(Collect::Cancel),
        Some(value) if value.is_empty() => match cwd_default {
            Some(path) => path,
            None => {
                return Err(fail_val(
                    SetupAction::Create,
                    Some("repository"),
                    None,
                    "empty response cannot accept an undisplayed default",
                )
                .into());
            }
        },
        Some(value) => PathBuf::from(value),
    };
    let mut repos = vec![first];
    loop {
        match prompt(
            stderr,
            stdin,
            "Additional repository (empty to finish)",
            None,
        )? {
            None => return Err(Collect::Cancel),
            Some(value) if value.is_empty() => break,
            Some(value) => repos.push(PathBuf::from(value)),
        }
    }
    Ok(repos)
}

fn collect_path_field(
    supplied: Option<&PathBuf>,
    prompting: bool,
    label: &str,
    default: Option<PathBuf>,
    stdin: &mut dyn BufRead,
    stderr: &mut dyn Write,
    field: &'static str,
) -> Result<PathBuf, Collect> {
    if let Some(path) = supplied {
        return Ok(path.clone());
    }
    if prompting {
        let shown = default.as_ref().and_then(|p| p.to_str());
        match prompt(stderr, stdin, label, shown)? {
            None => Err(Collect::Cancel),
            Some(value) if value.is_empty() => {
                if shown.is_some() {
                    default.ok_or_else(|| {
                        fail_val(
                            SetupAction::Create,
                            Some(field),
                            None,
                            "empty response cannot accept an undisplayed default",
                        )
                        .into()
                    })
                } else {
                    Err(fail_val(
                        SetupAction::Create,
                        Some(field),
                        None,
                        "empty response cannot accept an undisplayed default",
                    )
                    .into())
                }
            }
            Some(value) => Ok(PathBuf::from(value)),
        }
    } else if let Some(path) = default {
        Ok(path)
    } else {
        Err(fail_val(
            SetupAction::Inspect,
            Some(field),
            None,
            "missing required path; supply an explicit value when HOME/state bases are unavailable",
        )
        .into())
    }
}

fn collect_u64(
    supplied: Option<u64>,
    prompting: bool,
    label: &str,
    default: u64,
    stdin: &mut dyn BufRead,
    stderr: &mut dyn Write,
    field: &'static str,
) -> Result<u64, Collect> {
    if let Some(value) = supplied {
        return Ok(value);
    }
    if prompting {
        let shown = if matches!(field, "floor_bytes" | "warn_bytes") {
            format!("{default} {}", readable_bytes(default))
        } else {
            default.to_string()
        };
        match prompt(stderr, stdin, label, Some(&shown))? {
            None => Err(Collect::Cancel),
            Some(value) if value.is_empty() => Ok(default),
            Some(value) => {
                let token = value.split_whitespace().next().unwrap_or(&value);
                token.parse().map_err(|_| {
                    Collect::from(fail_val(
                        SetupAction::Create,
                        Some(field),
                        None,
                        "invalid unsigned integer",
                    ))
                })
            }
        }
    } else {
        Ok(default)
    }
}

fn collect_skills(
    args: &SetupArgs,
    prompting: bool,
    stdin: &mut dyn BufRead,
    stderr: &mut dyn Write,
) -> Result<SkillsSelection, Collect> {
    if let Some(skills) = args.skills {
        return Ok(map_skills(skills));
    }
    if prompting {
        match prompt(stderr, stdin, "Skills (none/standard/all)", Some("none"))? {
            None => Err(Collect::Cancel),
            Some(value) if value.is_empty() || value == "none" => Ok(SkillsSelection::None),
            Some(value) if value == "standard" => Ok(SkillsSelection::Standard),
            Some(value) if value == "all" => Ok(SkillsSelection::All),
            Some(_) => Err(fail_val(
                SetupAction::Inspect,
                Some("skills"),
                None,
                "skills must be none, standard, or all",
            )
            .into()),
        }
    } else {
        Ok(SkillsSelection::None)
    }
}

fn map_skills(skills: SkillsArg) -> SkillsSelection {
    match skills {
        SkillsArg::None => SkillsSelection::None,
        SkillsArg::Standard => SkillsSelection::Standard,
        SkillsArg::All => SkillsSelection::All,
    }
}

fn prompt(
    stderr: &mut dyn Write,
    stdin: &mut dyn BufRead,
    label: &str,
    default: Option<&str>,
) -> Result<Option<String>, Collect> {
    match default {
        Some(default) => write!(stderr, "{label} [{default}]: "),
        None => write!(stderr, "{label}: "),
    }
    .and_then(|_| stderr.flush())
    .map_err(|err| fail_val(SetupAction::Inspect, Some("prompt"), None, err.to_string()))?;
    read_line(stdin)
}

fn read_line(stdin: &mut dyn BufRead) -> Result<Option<String>, Collect> {
    let mut line = String::new();
    match stdin.read_line(&mut line) {
        Ok(0) => Ok(None),
        Ok(_) => Ok(Some(line.trim_end_matches(['\n', '\r']).trim().to_owned())),
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
        Err(err) => {
            Err(fail_val(SetupAction::Inspect, Some("prompt"), None, err.to_string()).into())
        }
    }
}

fn validate_repositories(paths: &[PathBuf], roots: &[PathBuf]) -> Result<Vec<PathBuf>, Fail> {
    if paths.is_empty() {
        return Err(fail_val(
            SetupAction::Inspect,
            Some("repository"),
            None,
            "at least one repository is required",
        ));
    }
    admit_git_version()?;
    let mut out = Vec::new();
    for path in paths {
        out.push(validate_one_repository(path, roots)?);
    }
    Ok(out)
}

fn admit_git_version() -> Result<(), Fail> {
    let output = git(None, &["version"])?;
    crate::inspection::require_supported_git_version(&output).map_err(|_| {
        fail_val(
            SetupAction::Inspect,
            Some("repository"),
            None,
            "unsupported Git version",
        )
    })
}

fn validate_one_repository(path: &Path, roots: &[PathBuf]) -> Result<PathBuf, Fail> {
    let path = validate_path(path, true).map_err(|_| {
        fail_val(
            SetupAction::Inspect,
            Some("repository"),
            Some(path),
            "repository must be an absolute canonical local path",
        )
    })?;
    crate::doctor::precheck(&path).map_err(|reason| {
        fail_val(
            SetupAction::Inspect,
            Some("repository"),
            Some(&path),
            reason,
        )
    })?;
    let bare = git(Some(&path), &["rev-parse", "--is-bare-repository"])?;
    if String::from_utf8_lossy(&bare).trim() != "false" {
        return Err(fail_val(
            SetupAction::Inspect,
            Some("repository"),
            Some(&path),
            "bare repositories are not supported",
        ));
    }
    if managed_checkout_evidence(&path)? {
        return Err(fail_val(
            SetupAction::Inspect,
            Some("repository"),
            Some(&path),
            "linked managed task checkouts are not valid sources",
        ));
    }
    for root in roots {
        if contained(&path, root) {
            return Err(fail_val(
                SetupAction::Inspect,
                Some("repository"),
                Some(&path),
                "repository must not be inside a managed root",
            ));
        }
    }
    Ok(path)
}

fn managed_checkout_evidence(path: &Path) -> Result<bool, Fail> {
    let git_dir = git(
        Some(path),
        &["rev-parse", "--path-format=absolute", "--git-dir"],
    )?;
    let git_dir = PathBuf::from(String::from_utf8_lossy(&git_dir).trim());
    match fs::symlink_metadata(git_dir.join("work-lease.json")) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(fail_val(
            SetupAction::Inspect,
            Some("repository"),
            Some(path),
            "managed checkout evidence is inaccessible",
        )),
        Ok(_) => Ok(true),
    }
}

fn git(cwd: Option<&Path>, args: &[&str]) -> Result<Vec<u8>, Fail> {
    let mut command = Command::new(GIT);
    command.arg("--no-optional-locks");
    if let Some(cwd) = cwd {
        command.arg("-C").arg(cwd);
    }
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0");
    let output = crate::bounded_process::output(&mut command, Duration::from_secs(2), 1024 * 1024)
        .map_err(|reason| fail_val(SetupAction::Inspect, Some("repository"), cwd, reason))?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(fail_val(
            SetupAction::Inspect,
            Some("repository"),
            cwd,
            "Git command failed",
        ))
    }
}

fn writer_path(path: &Path, must_exist: bool, field: &'static str) -> Result<PathBuf, Fail> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(fail_val(
            SetupAction::Inspect,
            Some(field),
            Some(path),
            "path must be absolute and canonical",
        ));
    }
    let mut missing = false;
    let components: Vec<_> = path.ancestors().collect();
    for ancestor in components.into_iter().rev() {
        match fs::symlink_metadata(ancestor) {
            Ok(meta) => {
                if missing {
                    return Err(fail_val(
                        SetupAction::Inspect,
                        Some(field),
                        Some(path),
                        "path ancestry is inconsistent",
                    ));
                }
                if meta.file_type().is_symlink() {
                    return Err(fail_val(
                        SetupAction::Inspect,
                        Some(field),
                        Some(path),
                        "writer paths cannot include symlink ancestors",
                    ));
                }
                if ancestor != path && !meta.is_dir() {
                    return Err(fail_val(
                        SetupAction::Inspect,
                        Some(field),
                        Some(path),
                        "path ancestry must be directories",
                    ));
                }
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                if must_exist {
                    return Err(fail_val(
                        SetupAction::Inspect,
                        Some(field),
                        Some(path),
                        "required path is missing",
                    ));
                }
                missing = true;
            }
            Err(_) => {
                return Err(fail_val(
                    SetupAction::Inspect,
                    Some(field),
                    Some(path),
                    "path ancestry is inaccessible",
                ));
            }
        }
    }
    if !missing {
        if let Ok(real) = path.canonicalize() {
            if real != path {
                return Err(fail_val(
                    SetupAction::Inspect,
                    Some(field),
                    Some(path),
                    "path must be canonical",
                ));
            }
        }
    }
    Ok(path.to_path_buf())
}

fn writer_ancestors(path: &Path, allow_missing: bool) -> Result<(), Fail> {
    let present = fs::symlink_metadata(path).is_ok();
    writer_path(path, present && !allow_missing, "config_path").map(|_| ())
}

fn validate_overlaps(
    config: &Path,
    store: &Path,
    registry: &Path,
    repositories: &[PathBuf],
    roots: &[PathBuf],
) -> Result<(), Fail> {
    if store == registry || contained(store, registry) || contained(registry, store) {
        return Err(fail_val(
            SetupAction::Inspect,
            Some("store_dir"),
            Some(store),
            "store and registry must be distinct paths",
        ));
    }
    for forbidden in repositories.iter().chain(roots) {
        if contained(store, forbidden)
            || contained(registry, forbidden)
            || contained(forbidden, store)
            || contained(forbidden, registry)
        {
            return Err(fail_val(
                SetupAction::Inspect,
                Some("store_dir"),
                Some(store),
                "store and registry must be outside repositories and managed roots",
            ));
        }
    }
    if contained(config, store) || contained(config, registry) {
        return Err(fail_val(
            SetupAction::Inspect,
            Some("config_path"),
            Some(config),
            "configuration cannot be placed inside authority data",
        ));
    }
    for dest in skill_destinations() {
        if contained(&dest, store) || contained(&dest, registry) {
            return Err(fail_val(
                SetupAction::Inspect,
                Some("store_dir"),
                Some(store),
                "skill destinations cannot be placed inside authority data",
            ));
        }
    }
    Ok(())
}

fn skill_destinations() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(home) = nonempty("HOME") {
        let home = PathBuf::from(home);
        out.push(home.join(".agents"));
        out.push(home.join(".claude"));
        out.push(home.join(".codex"));
        out.push(home.join(".local/share/work-cli"));
    }
    if let Some(data) = nonempty("XDG_DATA_HOME") {
        out.push(PathBuf::from(data).join("work-cli"));
    }
    out
}

fn endpoint_absent(path: &Path, field: &'static str) -> Result<(), Fail> {
    match fs::symlink_metadata(path) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                match fs::symlink_metadata(parent) {
                    Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => Ok(()),
                    Ok(_) => Err(fail_val(
                        SetupAction::Inspect,
                        Some(field),
                        Some(path),
                        "endpoint ancestry is unsafe",
                    )),
                    Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
                    Err(_) => Err(fail_val(
                        SetupAction::Inspect,
                        Some(field),
                        Some(path),
                        "endpoint ancestry is inaccessible",
                    )),
                }
            } else {
                Ok(())
            }
        }
        Err(_) => Err(fail_val(
            SetupAction::Inspect,
            Some(field),
            Some(path),
            "endpoint is inaccessible",
        )),
        Ok(_) => Err(fail_val(
            SetupAction::Inspect,
            Some(field),
            Some(path),
            "existing store or registry endpoint is not adopted",
        )),
    }
}

fn endpoint_present(path: &Path) -> Result<bool, Fail> {
    match fs::symlink_metadata(path) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(fail_val(
            SetupAction::Inspect,
            Some("store_dir"),
            Some(path),
            "authority endpoint is inaccessible",
        )),
        Ok(_) => Ok(true),
    }
}

fn endpoints_absent(store: &Path, registry: &Path) -> Result<bool, Fail> {
    Ok(!endpoint_present(store)? && !endpoint_present(registry)?)
}

fn planned_directories(config: &Path, root: &Path, store: &Path, registry: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(parent) = config.parent() {
        push_missing_chain(parent, &mut dirs);
    }
    push_missing_chain(root, &mut dirs);
    if let Some(parent) = store.parent() {
        push_missing_chain(parent, &mut dirs);
    }
    if let Some(parent) = registry.parent() {
        push_missing_chain(parent, &mut dirs);
    }
    dirs
}

fn push_missing_chain(path: &Path, dirs: &mut Vec<PathBuf>) {
    let mut missing = Vec::new();
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(_) => break,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                missing.push(ancestor.to_path_buf());
            }
            Err(_) => break,
        }
    }
    missing.reverse();
    for path in missing {
        if !dirs.iter().any(|existing| existing == &path) {
            dirs.push(path);
        }
    }
}

fn materialize_directories(planned: &[PathBuf], created: &mut Vec<PathBuf>) -> Result<(), Fail> {
    for path in planned {
        match fs::symlink_metadata(path) {
            Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => continue,
            Ok(_) => {
                return Err(fail_val(
                    SetupAction::Create,
                    Some("created_directories"),
                    Some(path),
                    "refusing to replace an existing non-directory",
                ));
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                step(WriterStep::CreateDir).map_err(|err| {
                    fail_val(
                        SetupAction::Create,
                        Some("created_directories"),
                        Some(path),
                        err.to_string(),
                    )
                })?;
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(path)
                    .map_err(|err| {
                        fail_val(
                            SetupAction::Create,
                            Some("created_directories"),
                            Some(path),
                            err.to_string(),
                        )
                    })?;
                created.push(path.clone());
            }
            Err(err) => {
                return Err(fail_val(
                    SetupAction::Create,
                    Some("created_directories"),
                    Some(path),
                    err.to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn current_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn owned_by_current_user(meta: &fs::Metadata) -> bool {
    let uid = meta.uid();
    // A private, per-thread metadata seam substitutes only one fixture inode's UID.
    // Production always uses the actual filesystem owner; no public selector exists.
    #[cfg(test)]
    let uid = if FOREIGN_FILE.with(|file| file.get()) == Some((meta.dev(), meta.ino())) {
        current_uid().wrapping_add(1)
    } else {
        uid
    };
    uid == current_uid()
}

fn private_owned_directory(meta: &fs::Metadata) -> bool {
    meta.is_dir()
        && !meta.file_type().is_symlink()
        && owned_by_current_user(meta)
        && meta.mode() & 0o077 == 0
}

fn validate_config_writer(path: &Path, action: SetupAction) -> Result<(), Fail> {
    writer_ancestors(path, false)?;
    let meta = fs::symlink_metadata(path).map_err(|err| io_reason(path, err))?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.nlink() != 1 {
        return Err(fail_val(
            action,
            Some("config_path"),
            Some(path),
            "configuration file must be a regular unlinked file",
        ));
    }
    if !owned_by_current_user(&meta) {
        return Err(fail_val(
            action,
            Some("config_path"),
            Some(path),
            "configuration file has unsafe ownership",
        ));
    }
    Ok(())
}

fn publish(
    plan: &SetupPlan,
    backup_path: &mut Option<PathBuf>,
    created: &mut Vec<PathBuf>,
) -> Result<(), Fail> {
    let path = &plan.config_path;
    writer_ancestors(path, plan.original.is_none())?;
    let parent = path.parent().ok_or_else(|| {
        fail_val(
            SetupAction::Create,
            Some("config_path"),
            Some(path),
            "configuration path has no parent",
        )
    })?;
    let lock = open_lock(parent)?;
    let result = (|| {
        let rendered = plan.rendered.as_deref().unwrap_or("");
        if let Some(original) = &plan.original {
            let current = reread(path)?;
            let meta = fs::symlink_metadata(path).map_err(|err| io_reason(path, err))?;
            if !owned_by_current_user(&meta) {
                return Err(fail_val(
                    plan.action,
                    Some("config_path"),
                    Some(path),
                    "configuration file has unsafe ownership",
                ));
            }
            if current.bytes != original.bytes
                || current.dev != original.dev
                || current.ino != original.ino
                || current.len != original.len
            {
                return Err(fail_val(
                    plan.action,
                    Some("config_path"),
                    Some(path),
                    "configuration changed after planning; refusing stale publication",
                ));
            }
            write_backup(parent, &original.bytes, backup_path, created)?;
            stage_and_replace(parent, path, rendered.as_bytes(), true)?;
        } else if fs::symlink_metadata(path).is_ok() {
            return Err(fail_val(
                SetupAction::Create,
                Some("config_path"),
                Some(path),
                "configuration appeared after planning; refusing clobber",
            ));
        } else {
            stage_and_replace(parent, path, rendered.as_bytes(), false)?;
        }
        Ok(())
    })();
    if lock.release().is_err() {
        let mut failure = match result {
            Ok(()) => {
                let mut failure = fail_val(
                    plan.action,
                    Some("lock"),
                    Some(&parent.join(LOCK_NAME)),
                    "configuration published but parent durability is uncertain",
                );
                failure.config_written = true;
                failure
            }
            Err(failure) => failure,
        };
        failure
            .reason
            .push_str("; setup-writer lock release is uncertain");
        return Err(failure);
    }
    result
}

// Unlock the owned open-file description before closing it: a concurrently
// spawned child can retain an alias even though Rust sets close-on-exec.
struct SetupLock {
    file: File,
    release_attempted: bool,
}

impl SetupLock {
    fn unlock(&mut self) -> io::Result<()> {
        // Never retry a failed release, including from Drop after release().
        self.release_attempted = true;
        step(WriterStep::Unlock)?;
        rustix::fs::flock(&self.file, rustix::fs::FlockOperation::Unlock).map_err(io::Error::from)
    }

    fn release(mut self) -> io::Result<()> {
        self.unlock()
    }
}

impl Drop for SetupLock {
    fn drop(&mut self) {
        if !self.release_attempted && self.unlock().is_err() {
            // Only unwind/direct scope-drop uses this fallback. Handled publish
            // returns use release() and carry uncertainty in the JSON report.
            eprintln!("setup-writer lock release is uncertain");
        }
    }
}

#[cfg(test)]
impl std::os::fd::AsFd for SetupLock {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.file.as_fd()
    }
}

fn open_lock(parent: &Path) -> Result<SetupLock, Fail> {
    let path = parent.join(LOCK_NAME);
    step(WriterStep::OpenLock).map_err(|err| {
        fail_val(
            SetupAction::Inspect,
            Some("lock"),
            Some(&path),
            err.to_string(),
        )
    })?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(&path)
        .map_err(|_| {
            fail_val(
                SetupAction::Inspect,
                Some("lock"),
                Some(&path),
                "cannot open setup-writer lock",
            )
        })?;
    let meta = file.metadata().map_err(|_| {
        fail_val(
            SetupAction::Inspect,
            Some("lock"),
            Some(&path),
            "cannot inspect setup-writer lock",
        )
    })?;
    if !meta.is_file()
        || meta.file_type().is_symlink()
        || !owned_by_current_user(&meta)
        || meta.nlink() != 1
        || meta.mode() & 0o077 != 0
    {
        return Err(fail_val(
            SetupAction::Inspect,
            Some("lock"),
            Some(&path),
            "setup-writer lock is unsafe",
        ));
    }
    step(WriterStep::Flock).map_err(|err| {
        fail_val(
            SetupAction::Inspect,
            Some("lock"),
            Some(&path),
            err.to_string(),
        )
    })?;
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(
        |err| {
            let reason = if err == rustix::io::Errno::WOULDBLOCK {
                "another setup writer holds the lock"
            } else {
                "cannot lock setup-writer lock"
            };
            fail_val(SetupAction::Inspect, Some("lock"), Some(&path), reason)
        },
    )?;
    Ok(SetupLock {
        file,
        release_attempted: false,
    })
}

fn stage_and_replace(parent: &Path, dest: &Path, bytes: &[u8], replace: bool) -> Result<(), Fail> {
    let stage_name = format!("{STAGE_PREFIX}{}", uuid::Uuid::now_v7());
    let stage = parent.join(&stage_name);
    step(WriterStep::StageCreate).map_err(|err| io_reason(dest, err))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(&stage)
        .map_err(|err| io_reason(&stage, err))?;
    step(WriterStep::StageWrite).map_err(|err| {
        let _ = fs::remove_file(&stage);
        io_reason(dest, err)
    })?;
    if let Err(err) = file.write_all(bytes) {
        let _ = fs::remove_file(&stage);
        return Err(io_reason(dest, err));
    }
    step(WriterStep::StageFlush).map_err(|err| {
        let _ = fs::remove_file(&stage);
        io_reason(dest, err)
    })?;
    if let Err(err) = file.flush() {
        let _ = fs::remove_file(&stage);
        return Err(io_reason(dest, err));
    }
    step(WriterStep::StageSync).map_err(|err| {
        let _ = fs::remove_file(&stage);
        io_reason(dest, err)
    })?;
    if let Err(err) = file.sync_all() {
        let _ = fs::remove_file(&stage);
        return Err(io_reason(dest, err));
    }
    drop(file);
    let dest_name = dest.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
        fail_val(
            SetupAction::Create,
            Some("config_path"),
            Some(dest),
            "configuration file name is not UTF-8",
        )
    })?;
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::DIRECTORY.bits() as i32)
        .open(parent)
        .map_err(|err| io_reason(parent, err))?;
    let result = if replace {
        step(WriterStep::RenameReplace)
            .map_err(|err| io_reason(dest, err))
            .and_then(|_| {
                rustix::fs::renameat(&dir, stage_name.as_str(), &dir, dest_name)
                    .map_err(io::Error::from)
                    .map_err(|err| io_reason(dest, err))
            })
    } else {
        step(WriterStep::RenameNoreplace)
            .map_err(|err| io_reason(dest, err))
            .and_then(|_| {
                rustix::fs::renameat_with(
                    &dir,
                    stage_name.as_str(),
                    &dir,
                    dest_name,
                    rustix::fs::RenameFlags::NOREPLACE,
                )
                .map_err(|err| {
                    if err == rustix::io::Errno::EXIST {
                        fail_val(
                            SetupAction::Create,
                            Some("config_path"),
                            Some(dest),
                            "configuration appeared after planning; refusing clobber",
                        )
                    } else {
                        io_reason(dest, io::Error::from(err))
                    }
                })
            })
    };
    if result.is_err() {
        let _ = fs::remove_file(&stage);
    }
    result
}

fn backup_name() -> String {
    #[cfg(test)]
    if let Some(name) = BACKUP_NAMES.with(|names| names.borrow_mut().pop()) {
        return name;
    }
    format!("config-{}.toml", uuid::Uuid::now_v7())
}

fn write_backup(
    parent: &Path,
    bytes: &[u8],
    backup_path: &mut Option<PathBuf>,
    created: &mut Vec<PathBuf>,
) -> Result<(), Fail> {
    let dir = parent.join(BACKUP_DIR_NAME);
    match fs::symlink_metadata(&dir) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&dir)
                .map_err(|err| io_reason(&dir, err))?;
            created.push(dir.clone());
        }
        Ok(meta) if private_owned_directory(&meta) => {}
        _ => {
            return Err(fail_val(
                SetupAction::Inspect,
                Some("backup_path"),
                Some(&dir),
                "backup directory is unsafe",
            ));
        }
    }
    for _ in 0..8 {
        let name = backup_name();
        let path = dir.join(&name);
        step(WriterStep::BackupCreate).map_err(|err| io_reason(&path, err))?;
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&path)
        {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(io_reason(&path, err)),
        };
        *backup_path = Some(path.clone());
        step(WriterStep::BackupWrite).map_err(|err| io_reason(&path, err))?;
        file.write_all(bytes).map_err(|err| io_reason(&path, err))?;
        step(WriterStep::BackupSync).map_err(|err| io_reason(&path, err))?;
        file.sync_all().map_err(|err| io_reason(&path, err))?;
        step(WriterStep::BackupDirSync).map_err(|err| io_reason(&dir, err))?;
        sync_path(&dir).map_err(|err| io_reason(&dir, err))?;
        return Ok(());
    }
    Err(fail_val(
        SetupAction::Inspect,
        Some("backup_path"),
        Some(&dir),
        "could not allocate a collision-safe backup name",
    ))
}

fn reread(path: &Path) -> Result<OriginalFile, Fail> {
    read_original(path).map(|(original, _)| original)
}

fn read_original(path: &Path) -> Result<(OriginalFile, ConfigDocument), Fail> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::NOFOLLOW).bits() as i32)
        .open(path)
        .map_err(|_| {
            fail_val(
                SetupAction::Inspect,
                Some("config_path"),
                Some(path),
                "cannot read configuration safely within size limit",
            )
        })?;
    let meta = file.metadata().map_err(|_| {
        fail_val(
            SetupAction::Inspect,
            Some("config_path"),
            Some(path),
            "cannot read configuration safely within size limit",
        )
    })?;
    if !meta.is_file() || meta.len() > MAX_CONFIG_BYTES {
        return Err(fail_val(
            SetupAction::Inspect,
            Some("config_path"),
            Some(path),
            "cannot read configuration safely within size limit",
        ));
    }
    if meta.nlink() != 1 {
        return Err(fail_val(
            SetupAction::Inspect,
            Some("config_path"),
            Some(path),
            "configuration file must not be a hard link",
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            fail_val(
                SetupAction::Inspect,
                Some("config_path"),
                Some(path),
                "cannot read configuration safely within size limit",
            )
        })?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(fail_val(
            SetupAction::Inspect,
            Some("config_path"),
            Some(path),
            "cannot read configuration safely within size limit",
        ));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        fail_val(
            SetupAction::Inspect,
            Some("config_path"),
            Some(path),
            "configuration is not valid UTF-8",
        )
    })?;
    let document = ConfigDocument::from_text(text).map_err(|err| {
        fail_val(
            SetupAction::Inspect,
            Some("config"),
            Some(path),
            sanitize_config_error(&err),
        )
    })?;
    Ok((
        OriginalFile {
            bytes,
            dev: meta.dev(),
            ino: meta.ino(),
            len: meta.len(),
        },
        document,
    ))
}

fn sync_path(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

fn io_reason(path: &Path, err: io::Error) -> Fail {
    fail_val(
        SetupAction::Inspect,
        Some("config_path"),
        Some(path),
        "setup I/O failed",
    )
    .with_io(err)
}

fn nonempty(key: &str) -> Option<std::ffi::OsString> {
    std::env::var_os(key).filter(|value| !value.is_empty())
}

fn default_root() -> Option<PathBuf> {
    nonempty("HOME").map(|home| PathBuf::from(home).join("worktrees"))
}

fn default_state_base() -> Option<PathBuf> {
    if let Some(state) = nonempty("XDG_STATE_HOME") {
        return Some(PathBuf::from(state).join("work"));
    }
    nonempty("HOME").map(|home| PathBuf::from(home).join(".local/state/work"))
}

fn default_store() -> Option<PathBuf> {
    default_state_base().map(|base| base.join("store"))
}

fn default_registry() -> Option<PathBuf> {
    default_state_base().map(|base| base.join("registry"))
}

fn contained(path: &Path, parent: &Path) -> bool {
    path == parent || path.starts_with(parent)
}

fn readable_bytes(value: u64) -> String {
    const GIB: u64 = 1_073_741_824;
    const MIB: u64 = 1_048_576;
    if value.is_multiple_of(GIB) {
        format!("({} GiB)", value / GIB)
    } else if value.is_multiple_of(MIB) {
        format!("({} MiB)", value / MIB)
    } else {
        let (unit, divisor) = if value >= GIB {
            ("GiB", GIB)
        } else if value >= MIB {
            ("MiB", MIB)
        } else if value >= 1024 {
            ("KiB", 1024)
        } else {
            return format!("({value} B)");
        };
        // The remainder is bounded by GiB, so computing hundredths cannot overflow.
        format!(
            "({}.{:02} {unit})",
            value / divisor,
            (value % divisor) * 100 / divisor
        )
    }
}

fn display_dirs(dirs: &[PathBuf]) -> Vec<String> {
    dirs.iter().map(|d| d.display().to_string()).collect()
}

fn sanitize_config_error(err: &crate::error::Error) -> String {
    let text = err.to_string();
    if let Some(rest) = text.strip_prefix("config error: ") {
        rest.to_owned()
    } else {
        "invalid configuration".into()
    }
}

fn sanitize_skill_error(message: &str) -> String {
    let first = message.split('(').next().unwrap_or(message).trim();
    if first.is_empty() {
        "skill installation failed".into()
    } else {
        first.to_owned()
    }
}

fn blank(action: SetupAction, path: Option<&Path>, outcome: SetupOutcome) -> SetupReport {
    SetupReport {
        config_path: path.map(|p| p.display().to_string()),
        action,
        outcome,
        config_written: false,
        authority_modified: false,
        created_directories: Vec::new(),
        backup_path: None,
        skills: SkillsReport {
            selection: SkillsSelection::None,
            status: SkillsStatus::Skipped,
            actions: Vec::new(),
        },
        next_steps: Vec::new(),
        error: None,
    }
}

fn fail(
    action: SetupAction,
    path: Option<&Path>,
    field: Option<&str>,
    location: Option<&Path>,
    reason: &str,
) -> SetupReport {
    let mut report = blank(action, path, SetupOutcome::Failed);
    report.error = Some(ReportError {
        field: field.map(str::to_owned),
        location: location.map(|p| p.display().to_string()),
        reason: reason.to_owned(),
    });
    report
}

fn cancelled(path: Option<&Path>) -> SetupReport {
    let mut report = blank(SetupAction::Inspect, path, SetupOutcome::Cancelled);
    report.error = Some(ReportError {
        field: Some("confirmation".into()),
        location: path.map(|p| p.display().to_string()),
        reason: "setup cancelled".into(),
    });
    report
}

fn fail_val(
    action: SetupAction,
    field: Option<&'static str>,
    location: Option<&Path>,
    reason: impl AsRef<str>,
) -> Fail {
    Fail {
        action,
        field,
        location: location.map(Path::to_path_buf),
        reason: reason.as_ref().to_owned(),
        config_written: false,
    }
}

impl Fail {
    fn into_report(self, path: Option<&Path>) -> SetupReport {
        let mut report = fail(
            self.action,
            path.or(self.location.as_deref()),
            self.field,
            self.location.as_deref().or(path),
            &self.reason,
        );
        report.config_written = self.config_written;
        if self.config_written {
            report.outcome = SetupOutcome::Partial;
        }
        report
    }

    fn with_io(self, err: io::Error) -> Self {
        let _ = err;
        self
    }
}

fn io_fail(plan: &SetupPlan, field: &'static str, err: io::Error) -> SetupReport {
    fail(
        plan.action,
        Some(&plan.config_path),
        Some(field),
        Some(&plan.config_path),
        "setup I/O failed",
    )
    .and_ignore(err)
}

impl SetupReport {
    fn and_ignore(self, _err: io::Error) -> Self {
        self
    }
}

fn step(step: WriterStep) -> io::Result<()> {
    #[cfg(test)]
    {
        OBSERVED.with(|observed| observed.borrow_mut().push(step));
        if FAIL_STEP.with(|fail| fail.get()) == Some(step) {
            return Err(io::Error::other("injected setup writer failure"));
        }
    }
    #[cfg(not(test))]
    {
        let _ = step;
    }
    Ok(())
}

#[allow(dead_code)]
pub(crate) fn writer_family(config_path: &Path) -> WriterFamily {
    let parent = config_path.parent().unwrap_or(config_path);
    WriterFamily {
        lock: parent.join(LOCK_NAME),
        backup_dir: parent.join(BACKUP_DIR_NAME),
        stage_prefix: STAGE_PREFIX,
    }
}

#[allow(dead_code)]
pub(crate) struct WriterFamily {
    pub lock: PathBuf,
    pub backup_dir: PathBuf,
    pub stage_prefix: &'static str,
}

#[cfg(test)]
use std::cell::{Cell, RefCell};

#[cfg(test)]
type InstallerStubResult = Result<Vec<SkillActionReport>, (Vec<SkillActionReport>, String)>;

#[cfg(test)]
thread_local! {
    static BACKUP_NAMES: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    static FOREIGN_FILE: Cell<Option<(u64, u64)>> = const { Cell::new(None) };
    static FAIL_STEP: Cell<Option<WriterStep>> = const { Cell::new(None) };
    static OBSERVED: RefCell<Vec<WriterStep>> = const { RefCell::new(Vec::new()) };
    static INSTALLER: RefCell<Option<InstallerStubResult>> = const { RefCell::new(None) };
}

#[cfg(test)]
fn take_installer_stub() -> Option<InstallerStubResult> {
    INSTALLER.with(|slot| slot.borrow_mut().take())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::{
        fs,
        io::Cursor,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
        process::Command,
    };

    #[derive(Parser, Debug)]
    #[command(no_binary_name = true)]
    struct Wire {
        #[command(flatten)]
        args: SetupArgs,
    }

    fn parse(args: &[&str]) -> Result<SetupArgs, clap::Error> {
        Wire::try_parse_from(args).map(|wire| wire.args)
    }

    #[test]
    fn setup_args_track_explicit_presence_including_skills_none_and_default_limits() {
        let args = parse(&[
            "--actor",
            "alice",
            "--repository",
            "/tmp/repo",
            "--repository",
            "/tmp/other",
            "--root",
            "/tmp/root",
            "--store-dir",
            "/tmp/store",
            "--trusted-registry",
            "/tmp/registry",
            "--repository-limit",
            "8",
            "--owner-limit",
            "4",
            "--floor-bytes",
            "1073741824",
            "--warn-bytes",
            "5368709120",
            "--skills",
            "none",
            "--add-repository",
            "/tmp/extra",
        ])
        .unwrap();
        assert_eq!(args.actor.as_deref(), Some("alice"));
        assert_eq!(args.repository.len(), 2);
        assert_eq!(args.repository_limit, Some(8));
        assert_eq!(args.owner_limit, Some(4));
        assert_eq!(args.floor_bytes, Some(1_073_741_824));
        assert_eq!(args.warn_bytes, Some(5_368_709_120));
        assert!(matches!(args.skills, Some(SkillsArg::None)));
        assert_eq!(args.add_repository.len(), 1);
        let empty = parse(&[]).unwrap();
        assert!(empty.actor.is_none());
        assert!(empty.skills.is_none());
        assert!(empty.repository_limit.is_none());
        assert!(!empty.yes && !empty.interactive && !empty.dry_run && !empty.check);
    }

    #[test]
    fn clap_owns_invalid_skills_and_unsigned_values() {
        assert!(parse(&["--skills", "maybe"]).is_err());
        assert!(parse(&["--repository-limit", "-1"]).is_err());
        assert!(parse(&["--floor-bytes", "nope"]).is_err());
    }

    #[test]
    fn contradictory_flags_are_json_owned() {
        for args in [
            parse(&["--interactive", "--yes"]).unwrap(),
            parse(&["--dry-run", "--yes"]).unwrap(),
            parse(&["--repository", "/tmp/a", "--add-repository", "/tmp/b"]).unwrap(),
            parse(&["--check", "--yes"]).unwrap(),
            parse(&["--check", "--actor", "alice"]).unwrap(),
            parse(&["--check", "--dry-run"]).unwrap(),
            parse(&["--check", "--root", "/tmp/root"]).unwrap(),
            parse(&["--check", "--skills", "standard"]).unwrap(),
        ] {
            let report = flag_error(&args).expect("flag error");
            assert_eq!(report.action, SetupAction::Inspect);
            assert_eq!(report.outcome, SetupOutcome::Failed);
            assert!(!report.config_written);
            assert!(report.skills.actions.is_empty());
            assert!(report.error.is_some());
        }
    }

    #[test]
    fn writer_family_describes_lock_stage_and_backup_without_incidental_names() {
        let config = PathBuf::from("/tmp/work/config.toml");
        let family = writer_family(&config);
        assert_eq!(family.lock.parent(), config.parent());
        assert_eq!(family.backup_dir.parent(), config.parent());
        assert!(family.stage_prefix.starts_with('.'));
        assert_ne!(family.lock, config);
        assert_ne!(family.backup_dir, config);
    }

    #[test]
    fn should_prompt_only_for_interactive_or_terminal_without_yes() {
        let mut args = parse(&[]).unwrap();
        args.interactive = true;
        args.yes = false;
        assert!(should_prompt(&args));
        args.interactive = false;
        args.yes = true;
        assert!(!should_prompt(&args));
    }

    fn init_repo(path: &Path) {
        fs::create_dir_all(path).unwrap();
        git(path, &["init", "-q", "-b", "main"]);
        git(
            path,
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
    }

    fn git(path: &Path, args: &[&str]) {
        let output = Command::new("/usr/bin/git")
            .args(["-c", "maintenance.auto=false"])
            .arg("-C")
            .arg(path)
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", path)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn git_validation_uses_doctor_precheck_and_allows_unrelated_linked_worktrees() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        let linked = temp.path().join("linked");
        let root = temp.path().join("worktrees");
        init_repo(&repo);
        fs::create_dir(&root).unwrap();
        git(
            &repo,
            &["worktree", "add", "-qb", "linked", linked.to_str().unwrap()],
        );
        assert!(validate_one_repository(&repo, std::slice::from_ref(&root)).is_ok());
        assert!(validate_one_repository(&linked, std::slice::from_ref(&root)).is_ok());
        let managed = root.join("task");
        git(
            &repo,
            &["worktree", "add", "-qb", "task", managed.to_str().unwrap()],
        );
        assert!(validate_one_repository(&managed, std::slice::from_ref(&root)).is_err());
        let other_root = temp.path().join("other-root");
        fs::create_dir(&other_root).unwrap();
        let elsewhere = other_root.join("task");
        git(
            &repo,
            &[
                "worktree",
                "add",
                "-qb",
                "elsewhere",
                elsewhere.to_str().unwrap(),
            ],
        );
        assert!(
            validate_one_repository(&elsewhere, std::slice::from_ref(&root)).is_ok(),
            "unrelated linked worktree outside proposed root stays eligible"
        );
        let git_file = fs::read_to_string(elsewhere.join(".git")).unwrap();
        let raw = git_file
            .trim()
            .strip_prefix("gitdir: ")
            .expect("worktree gitdir");
        let git_dir = {
            let path = PathBuf::from(raw);
            if path.is_absolute() {
                path
            } else {
                elsewhere.join(path)
            }
        };
        fs::write(git_dir.join("work-lease.json"), "{}").unwrap();
        assert!(
            validate_one_repository(&elsewhere, std::slice::from_ref(&root)).is_err(),
            "managed checkout evidence must be refused even outside the proposed root"
        );
    }

    #[test]
    fn interactive_empty_line_accepts_only_displayed_defaults_and_eof_cancels() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        fs::create_dir(&home).unwrap();
        let default = Some(home.join("worktrees"));
        let mut stderr = Vec::new();
        let mut stdin = Cursor::new("\n");
        let accepted = collect_path_field(
            None,
            true,
            "Managed root",
            default.clone(),
            &mut stdin,
            &mut stderr,
            "root",
        )
        .unwrap();
        assert_eq!(accepted, default.clone().unwrap());
        let mut stderr = Vec::new();
        let mut stdin = Cursor::new("\n");
        let err = collect_path_field(
            None,
            true,
            "Managed root",
            None,
            &mut stdin,
            &mut stderr,
            "root",
        )
        .unwrap_err();
        match err {
            Collect::Fail(fail) => assert!(fail.reason.contains("undisplayed")),
            _ => panic!("expected fail"),
        }
        let mut stderr = Vec::new();
        let mut stdin = Cursor::new("");
        assert!(matches!(
            collect_path_field(
                None,
                true,
                "Managed root",
                default,
                &mut stdin,
                &mut stderr,
                "root"
            ),
            Err(Collect::Cancel)
        ));
    }

    #[test]
    fn writer_steps_record_backup_sync_before_replace_and_parent_sync_after_both_modes() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("cfg");
        fs::create_dir(&parent).unwrap();
        let config = parent.join("config.toml");
        OBSERVED.with(|o| o.borrow_mut().clear());
        FAIL_STEP.with(|f| f.set(None));
        let plan = SetupPlan {
            action: SetupAction::Create,
            config_path: config.clone(),
            rendered: Some("actor = \"alice\"\n".into()),
            original: None,
            create_directories: Vec::new(),
            skills: SkillsSelection::None,
            actor: Some("alice".into()),
            repositories: Vec::new(),
            roots: Vec::new(),
            store_dir: None,
            trusted_registry: None,
            repository_limit: None,
            owner_limit: None,
            floor_bytes: None,
            warn_bytes: None,
            guidance_root: None,
        };
        let mut backup = None;
        publish(&plan, &mut backup, &mut Vec::new()).unwrap();
        step(WriterStep::ParentSync).unwrap();
        sync_path(&parent).unwrap();
        let observed = OBSERVED.with(|o| o.borrow().clone());
        let stage_sync = observed.iter().position(|s| *s == WriterStep::StageSync);
        let noreplace = observed
            .iter()
            .position(|s| *s == WriterStep::RenameNoreplace);
        let parent_sync = observed.iter().position(|s| *s == WriterStep::ParentSync);
        assert!(
            stage_sync < noreplace && noreplace < parent_sync,
            "{observed:?}"
        );
        fs::write(&config, "actor = \"alice\"\nsecret = 1\n").unwrap();
        let original = read_original(&config).unwrap().0;
        OBSERVED.with(|o| o.borrow_mut().clear());
        let plan = SetupPlan {
            action: SetupAction::AddRepositories,
            config_path: config.clone(),
            rendered: Some("actor = \"alice\"\nsecret = 1\n".into()),
            original: Some(original),
            create_directories: Vec::new(),
            skills: SkillsSelection::None,
            actor: Some("alice".into()),
            repositories: Vec::new(),
            roots: Vec::new(),
            store_dir: None,
            trusted_registry: None,
            repository_limit: None,
            owner_limit: None,
            floor_bytes: None,
            warn_bytes: None,
            guidance_root: None,
        };
        let mut backup = None;
        publish(&plan, &mut backup, &mut Vec::new()).unwrap();
        step(WriterStep::ParentSync).unwrap();
        sync_path(&parent).unwrap();
        let observed = OBSERVED.with(|o| o.borrow().clone());
        let backup_sync = observed.iter().position(|s| *s == WriterStep::BackupSync);
        let backup_dir = observed
            .iter()
            .position(|s| *s == WriterStep::BackupDirSync);
        let replace = observed
            .iter()
            .position(|s| *s == WriterStep::RenameReplace);
        let parent_sync = observed.iter().position(|s| *s == WriterStep::ParentSync);
        assert!(
            backup_sync < backup_dir && backup_dir < replace && replace < parent_sync,
            "{observed:?}"
        );
        let backup = backup.expect("backup path");
        assert_eq!(
            fs::read(&backup).unwrap(),
            b"actor = \"alice\"\nsecret = 1\n"
        );
        assert_eq!(fs::symlink_metadata(&config).unwrap().mode() & 0o777, 0o600);
    }

    #[test]
    fn injected_writer_failures_preserve_unknown_bytes_and_set_partial_after_publish() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("cfg");
        fs::create_dir(&parent).unwrap();
        let config = parent.join("config.toml");
        fs::write(&config, "keep = true\n").unwrap();
        let original = read_original(&config).unwrap().0;
        let plan = SetupPlan {
            action: SetupAction::AddRepositories,
            config_path: config.clone(),
            rendered: Some("keep = true\n".into()),
            original: Some(original),
            create_directories: Vec::new(),
            skills: SkillsSelection::None,
            actor: None,
            repositories: Vec::new(),
            roots: Vec::new(),
            store_dir: None,
            trusted_registry: None,
            repository_limit: None,
            owner_limit: None,
            floor_bytes: None,
            warn_bytes: None,
            guidance_root: None,
        };
        FAIL_STEP.with(|f| f.set(Some(WriterStep::RenameReplace)));
        let mut backup = None;
        assert!(publish(&plan, &mut backup, &mut Vec::new()).is_err());
        FAIL_STEP.with(|f| f.set(None));
        assert_eq!(fs::read(&config).unwrap(), b"keep = true\n");
        let meta = fs::symlink_metadata(&config).unwrap();
        assert_eq!(meta.nlink(), 1);
    }

    #[test]
    fn setup_plan_and_report_are_crate_private_shapes() {
        let report = blank(
            SetupAction::Inspect,
            Some(Path::new("/tmp/config.toml")),
            SetupOutcome::Success,
        );
        assert!(!report.authority_modified);
        assert!(report.config_path.is_some());
        let _plan = SetupPlan {
            action: SetupAction::Create,
            config_path: PathBuf::from("/tmp/config.toml"),
            rendered: None,
            original: None,
            create_directories: Vec::new(),
            skills: SkillsSelection::None,
            actor: None,
            repositories: Vec::new(),
            roots: Vec::new(),
            store_dir: None,
            trusted_registry: None,
            repository_limit: None,
            owner_limit: None,
            floor_bytes: None,
            warn_bytes: None,
            guidance_root: None,
        };
    }

    #[test]
    fn interactive_open_uses_registered_readonly_store() {
        let temp = tempfile::tempdir().unwrap();
        let store = temp.path().join("store");
        let registry = temp.path().join("registry");
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        let config = crate::config::Config {
            store_dir: Some(store.clone()),
            trusted_registry: Some(registry.clone()),
            roots: vec![root.clone()],
            ..crate::config::Config::default()
        };
        assert!(crate::interactive::open(&config).is_err());
        assert!(
            crate::store::Store::open_existing_registered_readonly(&registry, &store, &[root])
                .is_err()
        );
    }

    #[test]
    fn setup_lock_owner_releases_shared_description_on_every_scope_exit() {
        use std::os::fd::AsFd;

        for exit in ["normal", "explicit", "release error", "error", "unwind"] {
            let temp = tempfile::tempdir().unwrap();
            let owner = open_lock(temp.path()).unwrap();
            // A duplicate retains the same open-file description, just as inheritance does.
            let alias = owner.as_fd().try_clone_to_owned().unwrap();
            let blocked = open_lock(temp.path())
                .err()
                .expect("owner must serialize writers");
            assert!(blocked
                .reason
                .contains("another setup writer holds the lock"));
            match exit {
                "normal" => drop(owner),
                "explicit" => owner.release().unwrap(),
                "release error" => {
                    FAIL_STEP.with(|slot| slot.set(Some(WriterStep::Unlock)));
                    let result = owner.release();
                    FAIL_STEP.with(|slot| slot.set(None));
                    assert!(result.is_err());
                    let blocked = open_lock(temp.path())
                        .err()
                        .expect("no hidden unlock retry");
                    assert!(blocked
                        .reason
                        .contains("another setup writer holds the lock"));
                    // Only the test cleans up its deliberately failed release.
                    rustix::fs::flock(&alias, rustix::fs::FlockOperation::Unlock).unwrap();
                }
                "error" => {
                    fn early_return(owner: SetupLock) -> io::Result<()> {
                        let _owner = owner;
                        Err(io::Error::other("early return"))
                    }
                    let result = early_return(owner);
                    assert!(result.is_err());
                }
                "unwind" => {
                    assert!(std::panic::catch_unwind(move || {
                        let _owner = owner;
                        panic!("exercise setup-lock unwind release");
                    })
                    .is_err());
                }
                _ => unreachable!(),
            }
            let next = open_lock(temp.path()).unwrap_or_else(|err| {
                panic!("{exit}: owner release must unlock despite a live alias: {err:?}")
            });
            // Even an explicit unlock through the old description cannot release a new owner.
            rustix::fs::flock(&alias, rustix::fs::FlockOperation::Unlock).unwrap();
            drop(alias);
            let blocked = open_lock(temp.path())
                .err()
                .expect("new owner still holds lock");
            assert!(blocked
                .reason
                .contains("another setup writer holds the lock"));
            drop(next);
            drop(open_lock(temp.path()).unwrap());
        }
    }

    #[test]
    fn lock_release_failures_report_publication_and_preserve_earlier_errors() {
        for appeared in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let config = temp.path().join("config.toml");
            let mut plan = plan_with(
                SetupAction::Create,
                config.clone(),
                Some("actor = \"alice\"\n".into()),
                None,
            );
            if appeared {
                fs::write(&config, b"unknown bytes").unwrap();
            }
            plan.skills = SkillsSelection::Standard;
            INSTALLER.with(|slot| *slot.borrow_mut() = Some(Ok(Vec::new())));
            FAIL_STEP.with(|slot| slot.set(Some(WriterStep::Unlock)));
            let report = mutate(plan);
            FAIL_STEP.with(|slot| slot.set(None));
            assert!(INSTALLER.with(|slot| slot.borrow_mut().take().is_some()));
            assert_eq!(report.config_written, !appeared, "{report:?}");
            assert_eq!(
                report.outcome,
                if appeared {
                    SetupOutcome::Failed
                } else {
                    SetupOutcome::Partial
                },
                "{report:?}"
            );
            let reason = &report.error.as_ref().unwrap().reason;
            assert!(reason.contains("lock release is uncertain"), "{report:?}");
            if appeared {
                assert!(reason.contains("appeared after planning"), "{report:?}");
            } else {
                assert!(reason.contains("durability is uncertain"), "{report:?}");
            }
            assert_eq!(
                fs::read(&config).unwrap(),
                if appeared {
                    b"unknown bytes".as_slice()
                } else {
                    b"actor = \"alice\"\n".as_slice()
                }
            );
            assert!(report.next_steps.is_empty());
            assert_eq!(report.skills.status, SkillsStatus::Skipped);
        }
    }

    #[test]
    fn contended_lock_and_stale_snapshot_preserve_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("cfg");
        fs::create_dir(&parent).unwrap();
        let config = parent.join("config.toml");
        fs::write(&config, "keep = true\n").unwrap();
        let family = writer_family(&config);
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&family.lock)
            .unwrap();
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
        let original = read_original(&config).unwrap().0;
        let plan = SetupPlan {
            action: SetupAction::AddRepositories,
            config_path: config.clone(),
            rendered: Some("keep = false\n".into()),
            original: Some(original),
            create_directories: Vec::new(),
            skills: SkillsSelection::None,
            actor: None,
            repositories: Vec::new(),
            roots: Vec::new(),
            store_dir: None,
            trusted_registry: None,
            repository_limit: None,
            owner_limit: None,
            floor_bytes: None,
            warn_bytes: None,
            guidance_root: None,
        };
        let mut backup = None;
        let err = publish(&plan, &mut backup, &mut Vec::new()).unwrap_err();
        assert!(err.reason.contains("holds the lock"), "{err:?}");
        assert_eq!(fs::read(&config).unwrap(), b"keep = true\n");
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::Unlock).unwrap();
        drop(lock);
        let original = read_original(&config).unwrap().0;
        fs::write(&config, "changed = true\n").unwrap();
        let plan = SetupPlan {
            original: Some(original),
            ..plan
        };
        let mut backup = None;
        let err = publish(&plan, &mut backup, &mut Vec::new()).unwrap_err();
        assert!(err.reason.contains("stale"), "{err:?}");
        assert_eq!(fs::read(&config).unwrap(), b"changed = true\n");
    }

    #[test]
    fn parent_sync_failure_after_publish_is_partial_with_config_written() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("cfg");
        fs::create_dir(&parent).unwrap();
        let config = parent.join("config.toml");
        fs::write(&config, "keep = true\n").unwrap();
        let original = read_original(&config).unwrap().0;
        let plan = SetupPlan {
            action: SetupAction::AddRepositories,
            config_path: config.clone(),
            rendered: Some("keep = true\nadded = 1\n".into()),
            original: Some(original),
            create_directories: Vec::new(),
            skills: SkillsSelection::None,
            actor: None,
            repositories: Vec::new(),
            roots: Vec::new(),
            store_dir: None,
            trusted_registry: None,
            repository_limit: None,
            owner_limit: None,
            floor_bytes: None,
            warn_bytes: None,
            guidance_root: None,
        };
        FAIL_STEP.with(|f| f.set(Some(WriterStep::ParentSync)));
        let report = mutate(plan);
        FAIL_STEP.with(|f| f.set(None));
        assert_eq!(report.outcome, SetupOutcome::Partial);
        assert!(report.config_written);
        assert!(report.error.as_ref().unwrap().reason.contains("uncertain"));
    }

    #[test]
    fn skill_consumer_maps_complete_producer_sequences() {
        INSTALLER.with(|slot| {
            *slot.borrow_mut() = Some(Err((
                vec![
                    SkillActionReport {
                        kind: "directory".into(),
                        target: "/tmp/data/work-cli".into(),
                        status: "completed".into(),
                    },
                    SkillActionReport {
                        kind: "snapshot".into(),
                        target: "/tmp/data/work-cli/skill-snapshots/ab".into(),
                        status: "completed".into(),
                    },
                    SkillActionReport {
                        kind: "pointer".into(),
                        target: "/tmp/data/work-cli/skill-current".into(),
                        status: "unknown".into(),
                    },
                ],
                "pointer durability unknown".into(),
            )));
        });
        let mut plan = SetupPlan {
            action: SetupAction::SkillsOnly,
            config_path: PathBuf::from("/tmp/config.toml"),
            rendered: None,
            original: None,
            create_directories: Vec::new(),
            skills: SkillsSelection::Standard,
            actor: None,
            repositories: Vec::new(),
            roots: Vec::new(),
            store_dir: None,
            trusted_registry: None,
            repository_limit: None,
            owner_limit: None,
            floor_bytes: None,
            warn_bytes: None,
            guidance_root: None,
        };
        let mut report = blank(plan.action, Some(&plan.config_path), SetupOutcome::Success);
        report.config_written = true;
        let err = install_selected(&mut plan, &mut report).unwrap_err();
        assert_eq!(err.skills.status, SkillsStatus::Unknown);
        assert_eq!(err.outcome, SetupOutcome::Partial);
        assert!(err.config_written);
        assert_eq!(err.skills.actions.len(), 3);
        assert_eq!(err.skills.actions[0].status, "completed");
        assert_eq!(err.skills.actions[1].status, "completed");
        assert_eq!(err.skills.actions[2].kind, "pointer");
        assert_eq!(err.skills.actions[2].status, "unknown");
        INSTALLER.with(|slot| {
            *slot.borrow_mut() = Some(Err((
                vec![
                    SkillActionReport {
                        kind: "directory".into(),
                        target: "/tmp/data/work-cli".into(),
                        status: "completed".into(),
                    },
                    SkillActionReport {
                        kind: "snapshot".into(),
                        target: "/tmp/snap".into(),
                        status: "completed".into(),
                    },
                    SkillActionReport {
                        kind: "pointer".into(),
                        target: "/tmp/pointer".into(),
                        status: "completed".into(),
                    },
                    SkillActionReport {
                        kind: "registration".into(),
                        target: "/tmp/home/.agents/skills/work-cli".into(),
                        status: "completed".into(),
                    },
                    SkillActionReport {
                        kind: "registration".into(),
                        target: "/tmp/home/.claude/skills/work-cli".into(),
                        status: "failed".into(),
                    },
                ],
                "later registration failed".into(),
            )));
        });
        let mut plan = SetupPlan {
            action: SetupAction::SkillsOnly,
            config_path: PathBuf::from("/tmp/config.toml"),
            rendered: None,
            original: None,
            create_directories: Vec::new(),
            skills: SkillsSelection::All,
            actor: None,
            repositories: Vec::new(),
            roots: Vec::new(),
            store_dir: None,
            trusted_registry: None,
            repository_limit: None,
            owner_limit: None,
            floor_bytes: None,
            warn_bytes: None,
            guidance_root: None,
        };
        let mut report = blank(plan.action, Some(&plan.config_path), SetupOutcome::Success);
        report.config_written = true;
        let err = install_selected(&mut plan, &mut report).unwrap_err();
        assert_eq!(err.skills.status, SkillsStatus::Failed);
        assert_eq!(err.outcome, SetupOutcome::Partial);
        assert_eq!(err.skills.actions.len(), 5);
        assert!(err
            .skills
            .actions
            .iter()
            .any(|a| a.kind == "registration" && a.status == "completed"));
        assert!(err
            .skills
            .actions
            .iter()
            .any(|a| a.kind == "registration" && a.status == "failed"));
        INSTALLER.with(|slot| slot.borrow_mut().take());
    }

    fn plan_with(
        action: SetupAction,
        config: PathBuf,
        rendered: Option<String>,
        original: Option<OriginalFile>,
    ) -> SetupPlan {
        SetupPlan {
            action,
            config_path: config,
            rendered,
            original,
            create_directories: Vec::new(),
            skills: SkillsSelection::None,
            actor: Some("alice".into()),
            repositories: Vec::new(),
            roots: Vec::new(),
            store_dir: None,
            trusted_registry: None,
            repository_limit: None,
            owner_limit: None,
            floor_bytes: None,
            warn_bytes: None,
            guidance_root: None,
        }
    }

    fn physical_snapshot(root: &Path) -> std::collections::BTreeMap<PathBuf, String> {
        fn visit(path: &Path, out: &mut std::collections::BTreeMap<PathBuf, String>) {
            let meta = fs::symlink_metadata(path).unwrap();
            let bytes = if meta.is_file() {
                Some(fs::read(path).unwrap())
            } else {
                None
            };
            let target = if meta.file_type().is_symlink() {
                Some(fs::read_link(path).unwrap())
            } else {
                None
            };
            out.insert(
                path.to_path_buf(),
                format!(
                    "{:?}",
                    (
                        meta.dev(),
                        meta.ino(),
                        meta.mode(),
                        meta.uid(),
                        meta.gid(),
                        meta.nlink(),
                        bytes,
                        target
                    )
                ),
            );
            if meta.is_dir() {
                for entry in fs::read_dir(path).unwrap() {
                    visit(&entry.unwrap().path(), out);
                }
            }
        }
        let mut out = std::collections::BTreeMap::new();
        visit(root, &mut out);
        out
    }

    #[test]
    fn mutate_orders_parent_sync_after_both_publication_modes() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("cfg");
        fs::create_dir(&parent).unwrap();
        let config = parent.join("config.toml");
        OBSERVED.with(|o| o.borrow_mut().clear());
        FAIL_STEP.with(|f| f.set(None));
        let report = mutate(plan_with(
            SetupAction::Create,
            config.clone(),
            Some("actor = \"alice\"\n".into()),
            None,
        ));
        assert_eq!(report.outcome, SetupOutcome::Success);
        let observed = OBSERVED.with(|o| o.borrow().clone());
        let noreplace = observed
            .iter()
            .position(|s| *s == WriterStep::RenameNoreplace);
        let parent_sync = observed.iter().position(|s| *s == WriterStep::ParentSync);
        assert!(noreplace < parent_sync, "{observed:?}");
        fs::write(&config, "actor = \"alice\"\nsecret = 1\n").unwrap();
        let original = read_original(&config).unwrap().0;
        OBSERVED.with(|o| o.borrow_mut().clear());
        let report = mutate(plan_with(
            SetupAction::AddRepositories,
            config,
            Some("actor = \"alice\"\nsecret = 1\n".into()),
            Some(original),
        ));
        assert_eq!(report.outcome, SetupOutcome::Success);
        let observed = OBSERVED.with(|o| o.borrow().clone());
        let backup_dir = observed
            .iter()
            .position(|s| *s == WriterStep::BackupDirSync);
        let replace = observed
            .iter()
            .position(|s| *s == WriterStep::RenameReplace);
        let parent_sync = observed.iter().position(|s| *s == WriterStep::ParentSync);
        assert!(
            backup_dir < replace && replace < parent_sync,
            "{observed:?}"
        );
    }

    #[test]
    fn late_backup_and_directory_failures_report_progress() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("cfg");
        fs::create_dir(&parent).unwrap();
        let config = parent.join("config.toml");
        fs::write(&config, "keep = true\n").unwrap();
        let original = read_original(&config).unwrap().0;
        FAIL_STEP.with(|f| f.set(Some(WriterStep::BackupWrite)));
        let report = mutate(plan_with(
            SetupAction::AddRepositories,
            config.clone(),
            Some("keep = true\nadded = 1\n".into()),
            Some(original.clone()),
        ));
        FAIL_STEP.with(|f| f.set(None));
        assert_ne!(report.outcome, SetupOutcome::Success);
        assert!(!report.config_written);
        assert_eq!(fs::read(&config).unwrap(), b"keep = true\n");
        assert!(
            report.backup_path.is_some(),
            "backup file created before write failure must be reported: {report:?}"
        );

        let original = read_original(&config).unwrap().0;
        FAIL_STEP.with(|f| f.set(Some(WriterStep::BackupSync)));
        let report = mutate(plan_with(
            SetupAction::AddRepositories,
            config.clone(),
            Some("keep = true\nadded = 1\n".into()),
            Some(original),
        ));
        FAIL_STEP.with(|f| f.set(None));
        assert!(!report.config_written);
        assert!(report.backup_path.is_some(), "{report:?}");

        let missing_parent = temp.path().join("missing/cfg");
        let missing_config = missing_parent.join("config.toml");
        let mut create = plan_with(
            SetupAction::Create,
            missing_config.clone(),
            Some("actor = \"alice\"\n".into()),
            None,
        );
        create.create_directories = vec![temp.path().join("missing"), missing_parent.clone()];
        FAIL_STEP.with(|f| f.set(Some(WriterStep::OpenLock)));
        let report = mutate(create);
        FAIL_STEP.with(|f| f.set(None));
        assert!(!report.config_written);
        assert!(
            !report.created_directories.is_empty(),
            "directories created before late I/O must be reported: {report:?}"
        );

        FAIL_STEP.with(|f| f.set(Some(WriterStep::RenameReplace)));
        let original = read_original(&config).unwrap().0;
        let report = mutate(plan_with(
            SetupAction::AddRepositories,
            config.clone(),
            Some("keep = true\n".into()),
            Some(original),
        ));
        FAIL_STEP.with(|f| f.set(None));
        assert!(!report.config_written);
        assert_eq!(fs::read(&config).unwrap(), b"keep = true\n");
        assert!(report.backup_path.is_some() || report.error.is_some());
    }

    #[test]
    fn writer_operation_fault_table_preserves_files_and_reports_retained_progress() {
        // Shared operations need one failure case each; ParentSync differs by publication mode.
        for (name, fault, replace, retained_backup) in [
            ("create directory", WriterStep::CreateDir, false, false),
            ("create stage", WriterStep::StageCreate, true, true),
            ("write stage", WriterStep::StageWrite, true, true),
            ("flush stage", WriterStep::StageFlush, true, true),
            ("sync stage", WriterStep::StageSync, true, true),
            ("create backup", WriterStep::BackupCreate, true, false),
            (
                "sync backup directory",
                WriterStep::BackupDirSync,
                true,
                true,
            ),
            (
                "publish without clobber",
                WriterStep::RenameNoreplace,
                false,
                false,
            ),
            ("lock writer", WriterStep::Flock, false, false),
            (
                "sync created config parent",
                WriterStep::ParentSync,
                false,
                false,
            ),
            (
                "sync replaced config parent",
                WriterStep::ParentSync,
                true,
                true,
            ),
        ] {
            // Every row mutates files, so it owns an independent disposable fixture.
            let temp = tempfile::tempdir().unwrap();
            let parent = temp.path().join("cfg");
            fs::create_dir(&parent).unwrap();
            let config = parent.join("config.toml");
            let family = writer_family(&config);
            let unknown_stage = parent.join(format!("{}unknown", family.stage_prefix));
            fs::write(&unknown_stage, b"unowned stage must survive").unwrap();
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&family.lock)
                .unwrap()
                .write_all(b"retained lock bytes")
                .unwrap();
            let original_bytes = "keep = true\n";
            let rendered = "keep = true\nadded = 1\n";
            let original = if replace {
                fs::write(&config, original_bytes).unwrap();
                Some(read_original(&config).unwrap().0)
            } else {
                None
            };
            let original_identity = original.as_ref().map(|file| (file.dev, file.ino));
            let mut plan = plan_with(
                if replace {
                    SetupAction::AddRepositories
                } else {
                    SetupAction::Create
                },
                config.clone(),
                Some(rendered.into()),
                original,
            );
            let planned = vec![
                temp.path().join("managed"),
                temp.path().join("managed/nested"),
            ];
            if !replace {
                plan.create_directories = planned.clone();
            }
            plan.skills = SkillsSelection::Standard;
            let before = physical_snapshot(temp.path());
            OBSERVED.with(|steps| steps.borrow_mut().clear());
            INSTALLER.with(|slot| *slot.borrow_mut() = Some(Ok(Vec::new())));
            FAIL_STEP.with(|slot| slot.set(Some(fault)));
            let report = mutate(plan);
            FAIL_STEP.with(|slot| slot.set(None));
            let installer_not_called = INSTALLER.with(|slot| slot.borrow_mut().take().is_some());
            let observed = OBSERVED.with(|steps| steps.borrow().clone());
            let before_release = observed
                .strip_suffix(&[WriterStep::Unlock])
                .unwrap_or(&observed);
            assert_eq!(before_release.last(), Some(&fault), "{name}: {observed:?}");
            assert!(!successful(&report), "{name}: {report:?}");
            let published = fault == WriterStep::ParentSync;
            assert_eq!(report.config_written, published, "{name}: {report:?}");
            assert_eq!(
                report.outcome,
                if published {
                    SetupOutcome::Partial
                } else {
                    SetupOutcome::Failed
                },
                "{name}: {report:?}"
            );
            assert!(report.error.is_some(), "{name}: {report:?}");
            if published {
                assert!(report.error.as_ref().unwrap().reason.contains("uncertain"));
            }
            assert!(!report.authority_modified);
            assert!(
                installer_not_called,
                "{name}: installer ran after writer failure"
            );
            assert_eq!(report.skills.status, SkillsStatus::Skipped);
            assert!(report.skills.actions.is_empty());
            assert!(report.next_steps.is_empty());

            let created = if replace {
                vec![family.backup_dir.clone()]
            } else if fault == WriterStep::CreateDir {
                Vec::new()
            } else {
                planned
            };
            assert_eq!(
                report.created_directories,
                display_dirs(&created),
                "{name}: {report:?}"
            );
            assert_eq!(
                report.backup_path.is_some(),
                retained_backup,
                "{name}: {report:?}"
            );
            let after = physical_snapshot(temp.path());
            // Preserve all pre-existing files, including the original inode before publication.
            // Parent link counts can legitimately increase as reported directories are retained.
            for (path, saved) in &before {
                if path == temp.path() || path == &parent || (published && path == &config) {
                    continue;
                }
                assert_eq!(after.get(path), Some(saved), "{name}: changed {path:?}");
            }
            let mut expected_paths: std::collections::BTreeSet<_> =
                before.keys().cloned().collect();
            for dir in &created {
                expected_paths.insert(dir.clone());
                assert_eq!(
                    fs::symlink_metadata(dir).unwrap().mode() & 0o777,
                    0o700,
                    "{name}: {dir:?}"
                );
            }
            if let Some(backup) = &report.backup_path {
                let backup = PathBuf::from(backup);
                assert_eq!(backup.parent(), Some(family.backup_dir.as_path()));
                assert_eq!(
                    fs::read(&backup).unwrap(),
                    original_bytes.as_bytes(),
                    "{name}"
                );
                assert_eq!(fs::symlink_metadata(&backup).unwrap().mode() & 0o777, 0o600);
                expected_paths.insert(backup);
            }
            if published {
                assert_eq!(fs::read_to_string(&config).unwrap(), rendered, "{name}");
                assert_eq!(fs::symlink_metadata(&config).unwrap().mode() & 0o777, 0o600);
                let meta = fs::symlink_metadata(&config).unwrap();
                assert_eq!(meta.nlink(), 1);
                if replace {
                    assert_ne!(
                        Some((meta.dev(), meta.ino())),
                        original_identity,
                        "{name}: no replacement"
                    );
                }
                expected_paths.insert(config.clone());
            } else if !replace {
                assert!(
                    !after.contains_key(&config),
                    "{name}: unexpected publication"
                );
            }
            // Exact path inventory also proves owned-stage cleanup without deleting unknown stages.
            assert_eq!(
                after
                    .keys()
                    .cloned()
                    .collect::<std::collections::BTreeSet<_>>(),
                expected_paths,
                "{name}"
            );
        }
    }

    #[test]
    fn check_mode_fails_for_missing_and_unusable_configuration() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("missing.toml");
        let mut stderr = Vec::new();
        let report = check_mode(&missing, false, &mut stderr);
        assert_eq!(report.outcome, SetupOutcome::Failed);
        assert!(report.error.is_some());
        let config = temp.path().join("config.toml");
        fs::write(&config, "actor = [\n").unwrap();
        let mut stderr = Vec::new();
        let report = check_mode(&config, false, &mut stderr);
        assert_eq!(report.outcome, SetupOutcome::Failed);
    }

    #[test]
    fn inspect_existing_refuses_inaccessible_or_conflicting_authority() {
        let temp = tempfile::tempdir().unwrap();
        let store = temp.path().join("store");
        let registry = temp.path().join("registry");
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&store).unwrap();
        let text = format!(
            "actor = \"alice\"\nrepositories = []\nroots = [{root:?}]\nstore_dir = {store:?}\ntrusted_registry = {registry:?}\n"
        );
        let document = ConfigDocument::from_text(&text).unwrap();
        assert!(inspect_existing(temp.path(), &document).is_err());
        fs::create_dir(&registry).unwrap();
        assert!(inspect_existing(temp.path(), &document).is_err());
    }

    #[test]
    fn preview_u64_max_is_overflow_safe_independent_of_toml_admission() {
        let mut plan = plan_with(
            SetupAction::Create,
            PathBuf::from("/tmp/config.toml"),
            None,
            None,
        );
        plan.floor_bytes = Some(u64::MAX);
        plan.warn_bytes = Some(u64::MAX);
        let mut output = Vec::new();
        preview(&plan, &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();
        for field in ["floor_bytes", "warn_bytes"] {
            assert!(
                output.contains(&format!(
                    "{field}: 18446744073709551615 (17179869183.99 GiB)"
                )),
                "{output}"
            );
        }
    }

    #[test]
    fn backup_collisions_retain_unknown_types_bytes_and_identities() {
        use std::os::unix::{fs::symlink, net::UnixListener};
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join(BACKUP_DIR_NAME);
        fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let target = temp.path().join("unknown");
        fs::write(&target, b"unknown backup bytes").unwrap();
        fs::write(dir.join("regular"), b"retained regular").unwrap();
        fs::hard_link(&target, dir.join("hardlink")).unwrap();
        symlink(&target, dir.join("symlink")).unwrap();
        fs::create_dir(dir.join("directory")).unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            dir.join("fifo"),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            0,
        )
        .unwrap();
        let _socket = UnixListener::bind(dir.join("socket")).unwrap();
        let before = physical_snapshot(temp.path());
        let names = [
            "regular",
            "hardlink",
            "symlink",
            "directory",
            "fifo",
            "socket",
            "fresh",
        ];
        BACKUP_NAMES.with(|slot| {
            *slot.borrow_mut() = names.iter().rev().map(|name| (*name).into()).collect()
        });
        let mut backup = None;
        let mut created = Vec::new();
        write_backup(
            temp.path(),
            b"exact original bytes",
            &mut backup,
            &mut created,
        )
        .unwrap();
        BACKUP_NAMES.with(|slot| assert!(slot.borrow().is_empty()));
        assert!(created.is_empty());
        assert_eq!(backup, Some(dir.join("fresh")));
        assert_eq!(
            fs::read(dir.join("fresh")).unwrap(),
            b"exact original bytes"
        );
        assert_eq!(
            fs::metadata(dir.join("fresh")).unwrap().mode() & 0o777,
            0o600
        );
        let after = physical_snapshot(temp.path());
        assert_eq!(after.len(), before.len() + 1);
        for (path, saved) in before {
            assert_eq!(after.get(&path), Some(&saved), "{path:?}");
        }
    }

    #[test]
    fn foreign_lock_and_backup_metadata_refuse_and_preserve_unknown_artifacts() {
        for artifact in ["lock", "backup"] {
            let temp = tempfile::tempdir().unwrap();
            let config = temp.path().join("config.toml");
            fs::write(&config, "unknown = true\n").unwrap();
            let original = read_original(&config).unwrap().0;
            let plan = plan_with(
                SetupAction::AddRepositories,
                config.clone(),
                Some("unknown = true\nadded = 1\n".into()),
                Some(original),
            );
            let family = writer_family(&config);
            let path = if artifact == "lock" {
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&family.lock)
                    .unwrap()
                    .write_all(b"unknown lock")
                    .unwrap();
                family.lock.clone()
            } else {
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&family.backup_dir)
                    .unwrap();
                fs::write(family.backup_dir.join("retained"), b"unknown backup").unwrap();
                drop(open_lock(temp.path()).unwrap());
                family.backup_dir.clone()
            };
            let before = physical_snapshot(temp.path());
            let meta = fs::symlink_metadata(&path).unwrap();
            assert!(owned_by_current_user(&meta));
            FOREIGN_FILE.with(|file| file.set(Some((meta.dev(), meta.ino()))));
            let mut backup = None;
            let mut created = Vec::new();
            let err = publish(&plan, &mut backup, &mut created).unwrap_err();
            FOREIGN_FILE.with(|file| file.set(None));
            assert_eq!(
                err.field,
                Some(if artifact == "lock" {
                    "lock"
                } else {
                    "backup_path"
                })
            );
            assert!(err.reason.contains("unsafe"), "{err:?}");
            assert!(backup.is_none() && created.is_empty());
            assert_eq!(physical_snapshot(temp.path()), before);
            assert_eq!(fs::read(&config).unwrap(), b"unknown = true\n");
            let now = fs::symlink_metadata(&path).unwrap();
            assert_eq!(
                (now.dev(), now.ino(), now.mode(), now.nlink()),
                (meta.dev(), meta.ino(), meta.mode(), meta.nlink())
            );
            if artifact == "lock" {
                assert_eq!(fs::read(path).unwrap(), b"unknown lock");
                assert!(!family.backup_dir.exists());
            } else {
                assert_eq!(fs::read(path.join("retained")).unwrap(), b"unknown backup");
            }
            assert!(!fs::read_dir(temp.path()).unwrap().any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(family.stage_prefix)));
        }
    }

    #[test]
    fn foreign_config_is_reader_compatible_but_rejected_before_preview_or_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let repo = temp.path().join("repo");
        let extra = temp.path().join("extra");
        let store = temp.path().join("store");
        let registry = temp.path().join("registry");
        let config = temp.path().join("config.toml");
        fs::create_dir(&root).unwrap();
        init_repo(&repo);
        init_repo(&extra);
        drop(
            crate::store::Store::open_registered(&registry, &store, std::slice::from_ref(&root))
                .unwrap(),
        );
        let text = format!("actor = \"alice\"\nrepositories = [{repo:?}]\nroots = [{root:?}]\nstore_dir = {store:?}\ntrusted_registry = {registry:?}\n");
        fs::write(&config, &text).unwrap();
        // Ensure valid registration and parsing cannot mask the ownership predicate.
        let args = parse(&["--add-repository", extra.to_str().unwrap(), "--dry-run"]).unwrap();
        let plan =
            collect_existing(&args, &config, false, &mut Cursor::new(""), &mut Vec::new()).unwrap();
        let meta = fs::symlink_metadata(&config).unwrap();
        FOREIGN_FILE.with(|file| file.set(Some((meta.dev(), meta.ino()))));
        let inspect = run_with_path(
            parse(&[]).unwrap(),
            config.clone(),
            &mut Cursor::new(""),
            &mut Vec::new(),
        );
        assert_eq!(inspect.outcome, SetupOutcome::Success);
        let before = physical_snapshot(temp.path());
        for mode in ["--dry-run", "--yes"] {
            OBSERVED.with(|steps| steps.borrow_mut().clear());
            let report = run_with_path(
                parse(&["--add-repository", extra.to_str().unwrap(), mode]).unwrap(),
                config.clone(),
                &mut Cursor::new(""),
                &mut Vec::new(),
            );
            assert_eq!(report.outcome, SetupOutcome::Failed, "{report:?}");
            assert!(report.error.unwrap().reason.contains("ownership"));
            assert!(report.created_directories.is_empty());
            assert!(report.backup_path.is_none());
            assert!(!report.config_written);
            assert!(OBSERVED.with(|steps| steps.borrow().is_empty()));
            assert_eq!(physical_snapshot(temp.path()), before);
            let family = writer_family(&config);
            assert!(!family.lock.exists());
            assert!(!family.backup_dir.exists());
            assert!(!fs::read_dir(temp.path()).unwrap().any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(family.stage_prefix)));
            assert_eq!(fs::read_to_string(&config).unwrap(), text);
            let now = fs::symlink_metadata(&config).unwrap();
            assert_eq!((now.dev(), now.ino()), (meta.dev(), meta.ino()));
        }
        // A fresh observation under the lock must still reject changed eligibility.
        let err = publish(&plan, &mut None, &mut Vec::new()).unwrap_err();
        assert!(err.reason.contains("ownership"), "{err:?}");
        FOREIGN_FILE.with(|file| file.set(None));
    }

    #[test]
    fn next_steps_use_selected_registered_root() {
        let plan = SetupPlan {
            action: SetupAction::AddRepositories,
            config_path: PathBuf::from("/tmp/config.toml"),
            rendered: Some("x".into()),
            original: None,
            create_directories: Vec::new(),
            skills: SkillsSelection::None,
            actor: Some("alice".into()),
            repositories: vec![PathBuf::from("/tmp/a"), PathBuf::from("/tmp/b")],
            roots: vec![PathBuf::from("/tmp/root-b"), PathBuf::from("/tmp/root-a")],
            store_dir: None,
            trusted_registry: None,
            repository_limit: None,
            owner_limit: None,
            floor_bytes: None,
            warn_bytes: None,
            guidance_root: Some(PathBuf::from("/tmp/root-a")),
        };
        for action in [SetupAction::AddRepositories, SetupAction::Inspect] {
            let plan = SetupPlan {
                action,
                ..plan.clone()
            };
            let steps = next_steps(&plan, false);
            let start = &steps[0];
            let root_at = start.iter().position(|p| p == "--root").expect("root flag");
            assert_eq!(start[root_at + 1], "/tmp/root-a");
            let repo_at = start
                .iter()
                .position(|p| p == "--repository")
                .expect("repository flag");
            assert_eq!(start[repo_at + 1], "/tmp/a");
        }
    }
}
