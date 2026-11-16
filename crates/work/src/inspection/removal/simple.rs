//! Removal on macOS. `git worktree remove` without force refuses modified and
//! untracked files, so Git's own check replaces the retained inspection. Git
//! deletes ignored files silently, so the preview lists them first.
use super::*;

const SHOWN_PATHS: usize = 10;
// A removal killed part way leaves a half-deleted checkout, so allow a large tree.
const GIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);
const GIT_OUTPUT: usize = 16 * 1024 * 1024;

use crate::{allocate::Allocation, git::GitInvocation as Invocation};

// The inspection runner cannot reap on Darwin: killpg on a group whose leader
// has exited fails with EPERM. Use the bounded runner that start and finish use.
fn run_with(
    invocation: &Invocation,
    cwd: Option<&Path>,
    name: &str,
    args: &[&str],
    environment: impl FnOnce(&mut std::process::Command),
) -> Result<std::process::Output> {
    let binding = invocation
        .binding()
        .map_err(|_| "selected Git unavailable; capacity held")?;
    let command = binding
        .command(std::iter::empty::<&str>(), |command| {
            git_profile(command, cwd);
            environment(command);
            command.args(args);
        })
        .map_err(|_| "selected Git changed; capacity held")?;
    let unknown = "Git outcome unknown; capacity held";
    command
        .dispatch(|command| crate::bounded_process::output(command, GIT_TIMEOUT, GIT_OUTPUT))
        .map_err(|_| unknown)?
        .map_err(|reason| {
            if reason.starts_with("Git runtime limit") {
                format!("{name} timed out; capacity held")
            } else if reason.starts_with("Git capture limit") {
                format!("{name} output exceeds the limit; capacity held")
            } else {
                unknown.into()
            }
        })
}
fn run(
    invocation: &Invocation,
    cwd: Option<&Path>,
    name: &str,
    args: &[&str],
) -> Result<std::process::Output> {
    run_with(invocation, cwd, name, args, |_| {})
}
fn success(
    invocation: &Invocation,
    cwd: Option<&Path>,
    name: &str,
    args: &[&str],
) -> Result<Vec<u8>> {
    let output = run(invocation, cwd, name, args)?;
    if !output.status.success() {
        return Err(crate::git::failure_reason(
            &format!("{name} failed"),
            &output.stderr,
        ));
    }
    Ok(output.stdout)
}
// Work runs Git without the user's global config, but files that the user's
// global excludes name (such as Finder's .DS_Store) are ignored files to the
// user. Both the dirty check and the removal treat them as ignored.
fn excludes(invocation: &Invocation) -> Result<Vec<String>> {
    let variable = |name| std::env::var_os(name).filter(|v| !v.is_empty());
    let (Some(home), xdg) = (variable("HOME"), variable("XDG_CONFIG_HOME")) else {
        return Ok(Vec::new());
    };
    let output = run_with(
        invocation,
        None,
        "git config",
        &["config", "--global", "--get", "--path", "core.excludesFile"],
        |command| {
            command.env_remove("GIT_CONFIG_GLOBAL").env("HOME", &home);
            if let Some(xdg) = &xdg {
                command.env("XDG_CONFIG_HOME", xdg);
            }
        },
    )?;
    let path = match output.status.code() {
        Some(0) => PathBuf::from(std::ffi::OsStr::from_bytes(
            output.stdout.strip_suffix(b"\n").unwrap_or(&output.stdout),
        )),
        Some(1) => xdg
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(home).join(".config"))
            .join("git/ignore"),
        _ => {
            return Err(crate::git::failure_reason(
                "git config core.excludesFile failed",
                &output.stderr,
            ));
        }
    };
    let usable = path.is_absolute() && std::fs::metadata(&path).is_ok_and(|m| m.is_file());
    Ok(match path.to_str() {
        Some(path) if usable => vec!["-c".into(), format!("core.excludesFile={path}")],
        _ => Vec::new(),
    })
}
fn with<'a>(config: &'a [String], args: &[&'a str]) -> Vec<&'a str> {
    config
        .iter()
        .map(String::as_str)
        .chain(args.iter().copied())
        .collect()
}

fn printable(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .collect()
}
fn listed(paths: &[String]) -> String {
    let mut text = paths[..paths.len().min(SHOWN_PATHS)].join(", ");
    if paths.len() > SHOWN_PATHS {
        text.push_str(&format!(" and {} more", paths.len() - SHOWN_PATHS));
    }
    text
}
/// Refuses modified and untracked files; returns the ignored files. A wholly
/// untracked or ignored directory is one entry that ends in `/`.
fn clean(invocation: &Invocation, a: &Allocation, excludes: &[String]) -> Result<Vec<String>> {
    let output = success(
        invocation,
        Some(&a.destination),
        "git status",
        &with(
            excludes,
            &[
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=normal",
                "--ignored=traditional",
            ],
        ),
    )?;
    let (mut held, mut ignored) = (Vec::new(), Vec::new());
    let mut fields = output.split(|c| *c == 0).filter(|f| !f.is_empty());
    while let Some(field) = fields.next() {
        if field.len() < 4 || field[2] != b' ' {
            return Err("unexpected git status output".into());
        }
        let (code, path) = (&field[..2], printable(&field[3..]));
        if code == b"!!" {
            ignored.push(path);
            continue;
        }
        // A rename or copy entry is followed by its source path.
        if code.iter().any(|c| matches!(c, b'R' | b'C')) {
            fields.next();
        }
        held.push(path);
    }
    if !held.is_empty() {
        return Err(format!(
            "checkout has modified or untracked files: {}; commit, stash or delete them, then run the same command again; capacity held",
            listed(&held)
        ));
    }
    Ok(ignored)
}
fn object_id(text: &str) -> Result<String> {
    if !matches!(text.len(), 40 | 64)
        || !text.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err("invalid Git object id".into());
    }
    Ok(text.to_owned())
}
/// HEAD plus the commits that per-worktree refs name, which removal deletes with
/// the checkout's private administration. A tag is peeled to its commit; a ref
/// that names no commit refuses. Sorted and unique.
fn roots(invocation: &Invocation, a: &Allocation) -> Result<Vec<String>> {
    let cwd = Some(a.destination.as_path());
    let head = success(
        invocation,
        cwd,
        "git rev-parse HEAD",
        &["rev-parse", "--verify", "HEAD"],
    )?;
    let head = String::from_utf8(head).map_err(|_| "invalid HEAD")?;
    let mut roots = vec![object_id(head.strip_suffix('\n').ok_or("invalid HEAD")?)?];
    let refs = success(
        invocation,
        cwd,
        "git for-each-ref",
        &[
            "for-each-ref",
            "--format=%(refname)",
            "refs/worktree",
            "refs/bisect",
        ],
    )?;
    let refs = String::from_utf8(refs).map_err(|_| "invalid per-worktree refs")?;
    for name in refs.lines() {
        let peeled = format!("{name}^{{commit}}");
        let output = run(
            invocation,
            cwd,
            "git rev-parse",
            &["rev-parse", "-q", "--verify", "--end-of-options", &peeled],
        )?;
        let oid = String::from_utf8(output.stdout).unwrap_or_default();
        match oid.strip_suffix('\n') {
            Some(oid) if output.status.success() => roots.push(object_id(oid)?),
            _ => {
                return Err(format!(
                    "per-worktree ref {name} names no commit, and removal deletes it; delete or move it, then run the same command again; capacity held"
                ));
            }
        }
    }
    roots.sort();
    roots.dedup();
    Ok(roots)
}
/// The stored record is fixed, so a commit that is named now but not preserved
/// must be on a branch before Git deletes the checkout.
fn on_branches(invocation: &Invocation, a: &Allocation, preserved: &[String]) -> Result<()> {
    let mut loose = Vec::new();
    for oid in roots(invocation, a)? {
        if preserved.contains(&oid) {
            continue;
        }
        let holder = success(
            invocation,
            Some(&a.destination),
            "git for-each-ref",
            &[
                "for-each-ref",
                "--count=1",
                "--contains",
                &oid,
                "refs/heads",
            ],
        )?;
        if holder.is_empty() {
            loose.push(oid[..12].to_owned());
        }
    }
    if !loose.is_empty() {
        return Err(format!(
            "commits made since the interrupted removal are on no branch: {}; put them on a branch, then run the same command again; capacity held",
            listed(&loose)
        ));
    }
    Ok(())
}
fn preview(a: &Allocation, roots: &[String], ignored: Vec<String>) -> Report {
    let mut preview = report(a.checkout, a.destination.clone(), roots, false);
    if !ignored.is_empty() {
        preview.next_action = "removal deletes the ignored files listed; stop all agents and editors, then repeat with --confirm-stopped";
    }
    preview.ignored_files = ignored;
    preview
}
fn present(a: &Allocation) -> Result<bool> {
    match std::fs::symlink_metadata(&a.destination) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("checkout path: {e}")),
    }
}
/// One create-only ref for the checkout's last commit; an existing equal ref is kept.
fn preserve_head(invocation: &Invocation, a: &Allocation, roots: &[String]) -> Result<()> {
    for (reference, root) in references(a.checkout, roots).iter().zip(roots) {
        let cwd = Some(a.destination.as_path());
        let found = run(
            invocation,
            cwd,
            "git show-ref",
            &["show-ref", "--verify", "--hash", reference],
        )?;
        if found.status.success() {
            if found.stdout != format!("{root}\n").as_bytes() {
                return Err("recovery ref collision".into());
            }
            continue;
        }
        success(
            invocation,
            cwd,
            "git update-ref",
            &[
                "-c",
                "core.logAllRefUpdates=false",
                "update-ref",
                "--no-deref",
                reference,
                root,
                &"0".repeat(root.len()),
            ],
        )?;
    }
    Ok(())
}
fn registered(invocation: &Invocation, a: &Allocation) -> Result<bool> {
    let common = identity(a)?
        .common_git_dir
        .to_str()
        .ok_or("unsupported common path")?;
    let listing = success(
        invocation,
        None,
        "git worktree list",
        &["--git-dir", common, "worktree", "list", "--porcelain", "-z"],
    )?;
    let mut target = b"worktree ".to_vec();
    target.extend(a.destination.as_os_str().as_bytes());
    Ok(listing.split(|c| *c == 0).any(|field| field == target))
}
fn gone(invocation: &Invocation, a: &Allocation) -> Result<()> {
    if present(a)? {
        return Err("checkout directory still present; capacity held".into());
    }
    if registered(invocation, a)? {
        return Err("checkout still registered in Git; capacity held".into());
    }
    Ok(())
}
fn remove(invocation: &Invocation, a: &Allocation, excludes: &[String]) -> Result<()> {
    let common = identity(a)?
        .common_git_dir
        .to_str()
        .ok_or("unsupported common path")?;
    let destination = a.destination.to_str().ok_or("unsupported checkout path")?;
    // Git's own check runs `git status` with the repository's untracked-file
    // setting; `no` would let it delete untracked files.
    let output = run(
        invocation,
        None,
        "git worktree remove",
        &with(
            excludes,
            &[
                "-c",
                "status.showUntrackedFiles=normal",
                "--git-dir",
                common,
                "worktree",
                "remove",
                "--",
                destination,
            ],
        ),
    )?;
    if !output.status.success() {
        let reason = crate::git::failure_reason("git worktree remove refused", &output.stderr);
        return Err(format!(
            "{}; fix the cause, then run the same command again; capacity held",
            reason.strip_suffix([';', ',']).unwrap_or(&reason)
        ));
    }
    Ok(())
}
pub(crate) fn command(
    invocation: &Invocation,
    config: &Config,
    checkout: Uuid,
    confirmed: bool,
) -> Result<Report> {
    invocation
        .configure(config.git_path.clone())
        .map_err(|_| "Git selector changed")?;
    let mut store = checked(Store::open_existing_registered_mut(
        config
            .trusted_registry
            .as_deref()
            .ok_or("missing registry")?,
        config.store_dir.as_deref().ok_or("missing store")?,
        &config.roots,
    ))?;
    let guard = checked(crate::checkout_guard::CheckoutGuard::exclusive(
        &store, checkout,
    ))?;
    let allocation = completion(&store, checkout)?;
    let a = &allocation;
    let mut common = checked(AllocationCommonLock::acquire(
        &store,
        &identity(a)?.common_git_dir,
    ))?;
    let excludes = excludes(invocation)?;
    // The budget's deadline covers only record and publish, never a Git run.
    let (operation, record) = match history(&store, checkout)? {
        None => {
            let ignored = clean(invocation, a, &excludes)?;
            let roots = roots(invocation, a)?;
            if !confirmed {
                return Ok(preview(a, &roots, ignored));
            }
            let mut b = Budget::with_git(invocation);
            let record = record(&store, a, roots, &mut b)?;
            preserve_head(invocation, a, &record.roots)?;
            checked(common.revalidate(&store))?;
            checked(guard.revalidate(&store))?;
            let operation = Uuid::now_v7();
            publish(
                &mut store, &guard, a, operation, &record, "intent", None, &mut b,
            )?;
            (operation, record)
        }
        Some(h) if h.phase == "intent" => match (present(a)?, registered(invocation, a)?) {
            (false, false) => {
                if !confirmed {
                    return Err(
                        "Git removed the checkout; repeat with --confirm-stopped to release the capacity"
                            .into(),
                    );
                }
                checked(common.revalidate(&store))?;
                checked(guard.revalidate(&store))?;
                let mut b = Budget::with_git(invocation);
                for phase in ["native_succeeded", "removed"] {
                    publish(
                        &mut store,
                        &guard,
                        a,
                        h.operation,
                        &h.record,
                        phase,
                        None,
                        &mut b,
                    )?;
                }
                return Ok(report(
                    checkout,
                    a.destination.clone(),
                    &h.record.roots,
                    true,
                ));
            }
            (true, true) => {
                let ignored = clean(invocation, a, &excludes)?;
                on_branches(invocation, a, &h.record.roots)?;
                if !confirmed {
                    return Ok(preview(a, &h.record.roots, ignored));
                }
                let roots = h.record.roots.clone();
                if record(&store, a, roots, &mut Budget::with_git(invocation))? != h.record {
                    return Err("checkout changed since the interrupted removal; capacity held; correct it by hand".into());
                }
                preserve_head(invocation, a, &h.record.roots)?;
                (h.operation, h.record)
            }
            _ => {
                return Err("checkout directory and Git registration disagree after an interrupted removal; capacity held; correct it by hand".into());
            }
        },
        Some(h) => {
            gone(invocation, a)?;
            checked(common.revalidate(&store))?;
            checked(guard.revalidate(&store))?;
            let mut b = Budget::with_git(invocation);
            if h.phase == "native_succeeded" {
                if !confirmed {
                    return Err(
                        "native removal recorded; repeat with --confirm-stopped to reconcile capacity"
                            .into(),
                    );
                }
                publish(
                    &mut store,
                    &guard,
                    a,
                    h.operation,
                    &h.record,
                    "removed",
                    None,
                    &mut b,
                )?;
            }
            return Ok(report(
                checkout,
                a.destination.clone(),
                &h.record.roots,
                true,
            ));
        }
    };
    #[cfg(test)]
    super::tests::boundary("after_intent")?;
    checked(common.revalidate(&store))?;
    checked(guard.revalidate(&store))?;
    remove(invocation, a, &excludes)?;
    #[cfg(test)]
    super::tests::boundary("after_native")?;
    gone(invocation, a)?;
    let mut b = Budget::with_git(invocation);
    publish(
        &mut store,
        &guard,
        a,
        operation,
        &record,
        "native_succeeded",
        None,
        &mut b,
    )?;
    #[cfg(test)]
    super::tests::boundary("after_result")?;
    checked(common.revalidate(&store))?;
    publish(
        &mut store, &guard, a, operation, &record, "removed", None, &mut b,
    )?;
    Ok(report(checkout, a.destination.clone(), &record.roots, true))
}
