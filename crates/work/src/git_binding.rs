// Invocation-owned qualification. Included only by the owned Git module.
// Route validation is before/after observation, not atomic exec-by-FD or
// containment against malicious same-UID/root changes between observations.
use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
use std::path::Component;
use std::process::{Command, Output};
use std::time::Duration;

const REQUIRED_HELPERS: [&str; 3] = ["git-upload-pack", "git-receive-pack", "git-upload-archive"];
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const PROBE_BYTES: usize = 8192;
const PATH_BYTES: usize = 4096;
const SYSTEM_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum GitBindingReason {
    NotAbsolute,
    Unavailable,
    UnsafeAccess,
    AccessUnproven,
    NotExecutable,
    InvalidLayout,
    RouteLimit,
    Version(GitVersionError),
    ExecPathProtocol,
    ProbeFailed,
    CommandProfile,
    ProcessIncomplete(&'static str),
    Changed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GitBindingError {
    pub(crate) path: PathBuf,
    pub(crate) reason: GitBindingReason,
}

fn error(path: &Path, reason: GitBindingReason) -> GitBindingError {
    GitBindingError {
        path: path.to_owned(),
        reason,
    }
}

#[derive(Debug)]
pub(crate) struct GitRejection {
    pub(crate) candidate: GitCandidate,
    pub(crate) error: GitBindingError,
}

#[derive(Debug)]
pub(crate) struct GitSelectionFailure {
    pub(crate) rejections: Vec<GitRejection>,
    /// Incomplete probes/changed routes abort even automatic selection.
    pub(crate) ambiguous: bool,
}

#[derive(Debug)]
pub(crate) struct GitSelection<'a> {
    pub(crate) binding: GitBinding<'a>,
    pub(crate) rejections: Vec<GitRejection>,
}

trait GitAccessProof: std::fmt::Debug {
    fn prove(&self, path: &Path, metadata: &fs::Metadata) -> Result<(), GitBindingError>;
}

#[derive(Debug)]
struct SystemGitAccess;

impl GitAccessProof for SystemGitAccess {
    fn prove(&self, path: &Path, metadata: &fs::Metadata) -> Result<(), GitBindingError> {
        // Darwin ACL/effective-access observations are not implemented yet. Mode
        // bits there are NOT an access proof; neither accept nor ban all ACLs.
        #[cfg(not(target_os = "linux"))]
        {
            let _ = metadata;
            Err(error(path, GitBindingReason::AccessUnproven))
        }
        #[cfg(target_os = "linux")]
        {
            linux_access_policy(
                path,
                metadata.uid(),
                metadata.mode(),
                metadata.is_dir(),
                metadata.file_type().is_symlink(),
                rustix::process::geteuid().as_raw(),
            )
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_access_policy(
    path: &Path,
    uid: u32,
    mode: u32,
    directory: bool,
    symlink: bool,
    actor: u32,
) -> Result<(), GitBindingError> {
    // Linux POSIX ACL named/group write grants are bounded by the mode's group
    // class mask. With no group/other write, only the trusted owner can write.
    // A trusted-owner sticky directory protects trusted-owned child entries
    // against unlink/rename by unrelated principals (not against same UID/root).
    if (uid != 0 && uid != actor)
        || (!symlink && mode & 0o022 != 0 && !(directory && mode & 0o1000 != 0))
    {
        return Err(error(path, GitBindingReason::UnsafeAccess));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RouteEntry {
    path: PathBuf,
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    // Directory content changes are irrelevant to replacement/access proof.
    // File/symlink changes, including in-place executable upgrades, are not.
    data: Option<(u64, i64, i64, i64, i64)>,
    target: Option<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Route {
    canonical: PathBuf,
    entries: Vec<RouteEntry>,
}

#[derive(Clone, Copy)]
enum RequiredObject {
    Directory,
    Executable,
}

fn components(path: &Path) -> VecDeque<OsString> {
    let bytes = path.as_os_str().as_bytes();
    let mut parts = VecDeque::new();
    if path.is_absolute() {
        parts.push_back(OsString::from("/"));
    }
    // Path::components drops terminal dots and separators. Preserve dot steps
    // and represent a trailing slash as one: both require the preceding object
    // to be a directory, including when expanding a symlink target.
    parts.extend(
        bytes
            .split(|byte| *byte == b'/')
            .filter(|part| !part.is_empty())
            .map(|part| OsStr::from_bytes(part).to_owned()),
    );
    if bytes.ends_with(b"/") {
        parts.push_back(OsString::from("."));
    }
    parts
}

fn observe_route(
    path: &Path,
    required: RequiredObject,
    access: &dyn GitAccessProof,
) -> Result<Route, GitBindingError> {
    if !path.is_absolute() {
        return Err(error(path, GitBindingReason::NotAbsolute));
    }
    if path.as_os_str().as_bytes().len() > PATH_BYTES {
        return Err(error(path, GitBindingReason::RouteLimit));
    }
    let mut pending = components(path);
    let mut current = PathBuf::from("/");
    let mut entries = Vec::new();
    let mut links = 0;
    // Include root and every traversed route, including intermediate symlinks
    // and relative symlink target ancestors, not just canonicalize's endpoint.
    pending.pop_front();
    loop {
        if entries.len() >= 256 {
            return Err(error(path, GitBindingReason::RouteLimit));
        }
        let meta = fs::symlink_metadata(&current)
            .map_err(|_| error(&current, GitBindingReason::Unavailable))?;
        access.prove(&current, &meta)?;
        let target = if meta.file_type().is_symlink() {
            Some(
                fs::read_link(&current)
                    .map_err(|_| error(&current, GitBindingReason::Unavailable))?,
            )
        } else {
            None
        };
        entries.push(RouteEntry {
            path: current.clone(),
            device: meta.dev(),
            inode: meta.ino(),
            mode: meta.mode(),
            uid: meta.uid(),
            gid: meta.gid(),
            data: (!meta.is_dir()).then_some((
                meta.len(),
                meta.mtime(),
                meta.mtime_nsec(),
                meta.ctime(),
                meta.ctime_nsec(),
            )),
            target: target.clone(),
        });
        if let Some(target) = target {
            links += 1;
            if links > 40 || target.as_os_str().as_bytes().len() > PATH_BYTES {
                return Err(error(path, GitBindingReason::RouteLimit));
            }
            current.pop();
            if target.is_absolute() {
                current = PathBuf::from("/");
            }
            let mut expanded = components(&target);
            if target.is_absolute() {
                expanded.pop_front();
            }
            expanded.append(&mut pending);
            pending = expanded;
            // Observe the symlink target's parent before descending again.
            continue;
        }
        let Some(next) = pending.pop_front() else {
            match required {
                RequiredObject::Directory if !meta.is_dir() => {
                    return Err(error(&current, GitBindingReason::InvalidLayout))
                }
                RequiredObject::Executable
                    if !meta.is_file() || meta.mode() & 0o111 == 0 || meta.mode() & 0o6000 != 0 =>
                {
                    return Err(error(&current, GitBindingReason::NotExecutable))
                }
                _ => {}
            }
            rustix::fs::accessat(
                rustix::fs::CWD,
                &current,
                rustix::fs::Access::EXEC_OK,
                rustix::fs::AtFlags::EACCESS,
            )
            .map_err(|_| error(&current, GitBindingReason::NotExecutable))?;
            return Ok(Route {
                canonical: current,
                entries,
            });
        };
        if !meta.is_dir() {
            return Err(error(&current, GitBindingReason::InvalidLayout));
        }
        match Path::new(&next).components().next() {
            Some(Component::ParentDir) => {
                current.pop();
            }
            Some(Component::CurDir) => {}
            Some(Component::Normal(name)) => current.push(name),
            _ => return Err(error(path, GitBindingReason::InvalidLayout)),
        }
        if current.as_os_str().as_bytes().len() > PATH_BYTES {
            return Err(error(path, GitBindingReason::RouteLimit));
        }
    }
}

fn validate_route(
    path: &Path,
    required: RequiredObject,
    route: &Route,
    access: &dyn GitAccessProof,
) -> Result<(), GitBindingError> {
    if observe_route(path, required, access).as_ref() != Ok(route) {
        return Err(error(path, GitBindingReason::Changed));
    }
    Ok(())
}

fn sanitized_command(program: &Path) -> Command {
    let mut command = Command::new(program);
    command
        .current_dir("/")
        .env_clear()
        .env("PATH", SYSTEM_PATH)
        .env("HOME", "/nonexistent")
        .env("XDG_CONFIG_HOME", "/nonexistent")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GCM_INTERACTIVE", "never")
        .env("LC_ALL", "C");
    command
}

fn probe(
    candidate: &GitCandidate,
    route: &Route,
    argument: &str,
    access: &dyn GitAccessProof,
) -> Result<Vec<u8>, GitBindingError> {
    validate_route(&candidate.path, RequiredObject::Executable, route, access)?;
    let result = crate::bounded_process::output_aggregate(
        sanitized_command(&route.canonical).arg(argument),
        PROBE_TIMEOUT,
        PROBE_BYTES,
    );
    // Always revalidate after an attempted child, including transport failure.
    validate_route(&candidate.path, RequiredObject::Executable, route, access)?;
    let output = result
        .map_err(|reason| error(&candidate.path, GitBindingReason::ProcessIncomplete(reason)))?;
    if output.status.code().is_none() {
        return Err(error(
            &candidate.path,
            GitBindingReason::ProcessIncomplete(
                "Git qualification probe terminated without an exit code",
            ),
        ));
    }
    if !output.status.success() {
        return Err(error(&candidate.path, GitBindingReason::ProbeFailed));
    }
    Ok(output.stdout)
}

fn exec_path(output: &[u8], program: &Path) -> Result<PathBuf, GitBindingError> {
    let bytes = output
        .strip_suffix(b"\n")
        .filter(|b| {
            !b.is_empty()
                && b.len() <= PATH_BYTES
                && !b.iter().any(|c| matches!(c, 0 | b'\n' | b'\r'))
        })
        .ok_or_else(|| error(program, GitBindingReason::ExecPathProtocol))?;
    let path = PathBuf::from(OsStr::from_bytes(bytes));
    if !path.is_absolute() {
        return Err(error(program, GitBindingReason::ExecPathProtocol));
    }
    Ok(path)
}

#[derive(Debug)]
pub(crate) struct GitBinding<'a> {
    candidate: GitCandidate,
    canonical_program: PathBuf,
    version: GitVersion,
    helper_directory: PathBuf,
    executable: Route,
    helper_spelling: PathBuf,
    helper_route: Route,
    helpers: Vec<(PathBuf, Route)>,
    access: &'a dyn GitAccessProof,
}

impl GitBinding<'_> {
    pub(crate) fn candidate(&self) -> &GitCandidate {
        &self.candidate
    }
    pub(crate) fn canonical_program(&self) -> &Path {
        &self.canonical_program
    }
    pub(crate) fn version(&self) -> GitVersion {
        self.version
    }
    pub(crate) fn helper_directory(&self) -> &Path {
        &self.helper_directory
    }

    pub(crate) fn revalidate(&self) -> Result<(), GitBindingError> {
        validate_route(
            &self.candidate.path,
            RequiredObject::Executable,
            &self.executable,
            self.access,
        )?;
        validate_route(
            &self.helper_spelling,
            RequiredObject::Directory,
            &self.helper_route,
            self.access,
        )?;
        for (path, route) in &self.helpers {
            validate_route(path, RequiredObject::Executable, route, self.access)?;
        }
        Ok(())
    }

    /// The caller can retain its stronger command-specific profile, including
    /// env_clear/config/locale/hooks/no-lazy-fetch restrictions. Only the bound
    /// installation's GIT_EXEC_PATH is installed after that profile. Never use
    /// this baseline as a replacement for the caller's repository protections.
    pub(crate) fn command<I, S>(
        &self,
        args: I,
        profile: impl FnOnce(&mut Command),
    ) -> Result<BoundGitCommand<'_, '_>, GitBindingError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.revalidate()?;
        let mut command = sanitized_command(&self.canonical_program);
        command.args(args);
        profile(&mut command);
        if command.get_program() != self.canonical_program.as_os_str() {
            return Err(error(
                &self.canonical_program,
                GitBindingReason::CommandProfile,
            ));
        }
        command.env("GIT_EXEC_PATH", &self.helper_directory);
        Ok(BoundGitCommand {
            binding: self,
            command,
        })
    }
}

#[derive(Debug)]
pub(crate) struct GitDispatchError {
    /// False only when binding validation refused before the runner was called.
    /// Once attempted, do not retry/fallback or infer rollback/no-spawn.
    pub(crate) possibly_executed: bool,
    pub(crate) error: GitBindingError,
}

pub(crate) struct BoundGitCommand<'b, 'a> {
    binding: &'b GitBinding<'a>,
    command: Command,
}

impl BoundGitCommand<'_, '_> {
    /// Includes pre- AND post-dispatch validation. Nonzero Output status remains
    /// a caller-specific failure, never evidence that the child did not execute.
    pub(crate) fn output_aggregate(
        mut self,
        timeout: Duration,
        bytes: usize,
    ) -> Result<Output, GitDispatchError> {
        self.binding
            .revalidate()
            .map_err(|error| GitDispatchError {
                possibly_executed: false,
                error,
            })?;
        let result = crate::bounded_process::output_aggregate(&mut self.command, timeout, bytes);
        self.binding
            .revalidate()
            .map_err(|error| GitDispatchError {
                possibly_executed: true,
                error,
            })?;
        result.map_err(|reason| GitDispatchError {
            possibly_executed: true,
            error: error(
                &self.binding.canonical_program,
                GitBindingReason::ProcessIncomplete(reason),
            ),
        })
    }
}

fn qualify_candidate<'a>(
    candidate: &GitCandidate,
    access: &'a dyn GitAccessProof,
) -> Result<GitBinding<'a>, GitBindingError> {
    let executable = observe_route(&candidate.path, RequiredObject::Executable, access)?;
    let result = (|| {
        let version =
            require_supported_git_version(&probe(candidate, &executable, "--version", access)?)
                .map_err(|reason| error(&candidate.path, GitBindingReason::Version(reason)))?;
        let helper_spelling = exec_path(
            &probe(candidate, &executable, "--exec-path", access)?,
            &candidate.path,
        )?;
        let helper_route = observe_route(&helper_spelling, RequiredObject::Directory, access)?;
        let mut helpers = Vec::new();
        let helper_result: Result<(), GitBindingError> =
            REQUIRED_HELPERS.into_iter().try_for_each(|name| {
                let path = helper_route.canonical.join(name);
                let route = observe_route(&path, RequiredObject::Executable, access)?;
                helpers.push((path, route));
                Ok(())
            });
        // Retain and validate completed observations even if a later helper is
        // rejected. A known change must not become an ordinary layout rejection.
        validate_route(
            &helper_spelling,
            RequiredObject::Directory,
            &helper_route,
            access,
        )?;
        for (path, route) in &helpers {
            validate_route(path, RequiredObject::Executable, route, access)?;
        }
        helper_result?;
        let binding = GitBinding {
            candidate: candidate.clone(),
            canonical_program: executable.canonical.clone(),
            version,
            helper_directory: helper_route.canonical.clone(),
            executable: executable.clone(),
            helper_spelling,
            helper_route,
            helpers,
            access,
        };
        binding.revalidate()?;
        Ok(binding)
    })();
    validate_route(
        &candidate.path,
        RequiredObject::Executable,
        &executable,
        access,
    )?;
    result
}

fn qualify_candidates<'a>(
    candidates: &[GitCandidate],
    access: &'a dyn GitAccessProof,
) -> Result<GitSelection<'a>, GitSelectionFailure> {
    let mut rejections = Vec::new();
    for candidate in candidates {
        match qualify_candidate(candidate, access) {
            Ok(binding) => {
                return Ok(GitSelection {
                    binding,
                    rejections,
                })
            }
            Err(error) => {
                let ambiguous = matches!(
                    error.reason,
                    GitBindingReason::Changed | GitBindingReason::ProcessIncomplete(_)
                );
                rejections.push(GitRejection {
                    candidate: candidate.clone(),
                    error,
                });
                if ambiguous || candidate.source != GitSelectionSource::PlatformDefault {
                    return Err(GitSelectionFailure {
                        rejections,
                        ambiguous,
                    });
                }
            }
        }
    }
    Err(GitSelectionFailure {
        rejections,
        ambiguous: false,
    })
}

/// Qualify G1's ordered candidates once for this invocation. No environment
/// selector, arbitrary PATH search, setup write or dispatch-time rediscovery.
pub(crate) fn select_git(
    candidates: &[GitCandidate],
) -> Result<GitSelection<'static>, GitSelectionFailure> {
    qualify_candidates(candidates, &SystemGitAccess)
}
