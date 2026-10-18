//! Bounded inventory only. No allocation, repair, hooks, notifications or network.
use crate::{
    config::{validate_path, Config},
    error::Error,
    store::{self, Charge},
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
};

const ENTRY_LIMIT: usize = 10_000;
#[derive(Serialize)]
pub struct Report {
    pub version: u32,
    pub repositories: Vec<PathBuf>,
    pub inventory: Vec<Entry>,
    pub accounting: Accounting,
    pub managed_filesystem_count: Option<u64>,
    pub headroom: Vec<Headroom>,
    pub uncertainties: Vec<&'static str>,
    pub size_basis: &'static str,
}
#[derive(Serialize)]
pub struct Accounting {
    pub status: &'static str,
    pub charges: Vec<Charge>,
    pub reason: &'static str,
}
#[derive(Serialize)]
pub struct Entry {
    pub path: PathBuf,
    pub registered: bool,
    pub classification: &'static str,
    pub reason: &'static str,
    pub logical_bytes: Option<u64>,
}
#[derive(Serialize)]
pub struct Headroom {
    pub root: PathBuf,
    pub available_bytes: Option<u64>,
}

fn git(path: &Path, args: &[&str]) -> Option<Vec<u8>> {
    let o = Command::new("git")
        .arg("--no-optional-locks")
        .arg("-C")
        .arg(path)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .ok()?;
    o.status.success().then_some(o.stdout)
}
fn common(path: &Path) -> Option<PathBuf> {
    let b = git(
        path,
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
    )?;
    let p = PathBuf::from(std::str::from_utf8(&b).ok()?.trim_end_matches('\n'));
    validate_path(&p, true).ok()
}
fn metadata_text(path: &Path) -> Option<String> {
    let m = fs::symlink_metadata(path).ok()?;
    if !m.is_file() || m.file_type().is_symlink() || m.len() > 8192 {
        return None;
    }
    let mut text = String::new();
    fs::File::open(path)
        .ok()?
        .take(8193)
        .read_to_string(&mut text)
        .ok()?;
    (text.len() <= 8192).then_some(text)
}
fn valid_checkout(path: &Path, common_dir: &Path) -> bool {
    if validate_path(path, true).is_err() {
        return false;
    }
    let marker = path.join(".git");
    if marker == common_dir {
        return validate_path(&marker, true).is_ok()
            && metadata_text(&marker.join("HEAD")).is_some();
    }
    let Some(text) = metadata_text(&marker) else {
        return false;
    };
    let Some(private) = text.trim_end_matches('\n').strip_prefix("gitdir: ") else {
        return false;
    };
    let private = path.join(private);
    // Git may use relative pointer paths; canonicalize only after rejecting symlink components.
    if private
        .ancestors()
        .any(|p| fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink()))
    {
        return false;
    }
    let Ok(private) = private.canonicalize() else {
        return false;
    };
    if private.parent() != Some(common_dir.join("worktrees").as_path()) {
        return false;
    }
    let Some(backlink) = metadata_text(&private.join("gitdir")) else {
        return false;
    };
    let Some(relative) = metadata_text(&private.join("commondir")) else {
        return false;
    };
    let c = private.join(relative.trim_end_matches('\n'));
    if c.ancestors()
        .any(|p| fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink()))
    {
        return false;
    }
    Path::new(backlink.trim_end_matches('\n')) == marker
        && c.canonicalize().ok().as_deref() == Some(common_dir)
        && metadata_text(&private.join("HEAD")).is_some()
}
/// Apparent regular-file lengths only: no file contents, symlink traversal,
/// cross-device descent or special files. Any incomplete walk is unknown.
fn logical_size(path: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    fn walk(path: &Path, dev: u64, budget: &mut usize, depth: usize) -> Option<u64> {
        if *budget == 0 || depth > 32 {
            return None;
        }
        *budget -= 1;
        let m = fs::symlink_metadata(path).ok()?;
        if m.dev() != dev || m.file_type().is_symlink() {
            return None;
        }
        if m.is_file() {
            return Some(m.len());
        }
        if !m.is_dir() {
            return None;
        }
        let mut n = 0u64;
        for e in fs::read_dir(path).ok()? {
            n = n.checked_add(walk(&e.ok()?.path(), dev, budget, depth + 1)?)?;
        }
        Some(n)
    }
    let dev = fs::symlink_metadata(path).ok()?.dev();
    let mut budget = ENTRY_LIMIT;
    walk(path, dev, &mut budget, 0)
}

pub fn report(config: &Config) -> Result<Report, Error> {
    if config.roots.is_empty() || config.repositories.is_empty() {
        return Err(Error::Config(
            "doctor requires explicit repositories and managed roots".into(),
        ));
    }
    let mut roots = config
        .roots
        .iter()
        .map(|p| validate_path(p, true))
        .collect::<Result<Vec<_>, _>>()?;
    roots.sort();
    for (i, root) in roots.iter().enumerate() {
        if root.parent().is_none() || roots[i + 1..].iter().any(|p| p.starts_with(root)) {
            return Err(Error::Config("ambiguous managed roots".into()));
        }
    }
    let mut uncertainties = Vec::new();
    let mut repos = BTreeMap::new();
    for repo in &config.repositories {
        validate_path(repo, true)?;
        if let Some(c) = common(repo) {
            repos.entry(c).or_insert(repo);
        } else {
            uncertainties.push("repository identity unavailable");
        }
    }
    let mut entries = BTreeMap::new();
    for (c, repo) in &repos {
        let Some(list) = git(repo, &["worktree", "list", "--porcelain", "-z"]) else {
            uncertainties.push("Git registration inventory unavailable");
            continue;
        };
        let Ok(list) = std::str::from_utf8(&list) else {
            uncertainties.push("non-UTF8 registration unsupported");
            continue;
        };
        for field in list.split('\0') {
            if let Some(p) = field.strip_prefix("worktree ") {
                let path = PathBuf::from(p);
                if !path.is_absolute() {
                    uncertainties.push("invalid registration path");
                    continue;
                }
                let valid = valid_checkout(&path, c);
                entries.insert(path.clone(), Entry { logical_bytes: logical_size(&path), path, registered: true,
                    classification: if valid { "legacy" } else { "unknown" },
                    reason: if valid { "registered Git checkout; legacy/unmanaged candidate, managed identity not certified" }
                    else { "partial, missing or recreated checkout/private Git metadata; reconciliation required" } });
            }
        }
    }
    let registered: BTreeSet<_> = entries.keys().cloned().collect();
    let mut headroom = Vec::new();
    for root in &roots {
        let available_bytes = rustix::fs::statvfs(root)
            .ok()
            .and_then(|s| s.f_bavail.checked_mul(s.f_frsize));
        headroom.push(Headroom {
            root: root.clone(),
            available_bytes,
        });
        let Ok(children) = fs::read_dir(root) else {
            uncertainties.push("managed root unreadable");
            continue;
        };
        for (i, child) in children.enumerate() {
            if i >= 1000 {
                uncertainties.push("managed root child limit reached; inventory incomplete");
                break;
            }
            let Ok(child) = child else {
                uncertainties.push("managed root entry unreadable");
                continue;
            };
            let path = child.path();
            if registered.contains(&path) {
                continue;
            }
            let has_git_marker = fs::symlink_metadata(path.join(".git")).is_ok();
            let unsafe_path = validate_path(&path, true).is_err()
                || (has_git_marker && !repos.keys().any(|c| valid_checkout(&path, c)));
            entries.entry(path.clone()).or_insert_with(|| Entry { logical_bytes: logical_size(&path), path, registered: false,
                classification: if unsafe_path { "unknown" } else { "unmanaged" },
                reason: if unsafe_path { "unregistered partial/recreated path or malformed/missing Git metadata; reconciliation required" }
                    else { "unregistered immediate child; subtree not searched for nested checkouts" } });
        }
    }
    let charges = config
        .trusted_registry
        .as_ref()
        .zip(config.store_dir.as_ref())
        .and_then(|(registry, store)| store::report_existing(registry, store, &roots).ok());
    let status = if charges.is_some() {
        "available"
    } else {
        "unknown"
    };
    uncertainties.sort();
    uncertainties.dedup();
    Ok(Report { version: 1, repositories: repos.into_keys().collect(), inventory: entries.into_values().collect(),
        accounting: Accounting { status, charges: charges.unwrap_or_default(), reason: "accounting records lack checkout filesystem paths; cannot certify managed filesystem identity yet. Unknown means missing, partial, unsafe or unreadable authority/store evidence; no initialization or repair attempted" },
        managed_filesystem_count: None, headroom, uncertainties,
        size_basis: "bounded logical regular-file lengths, not allocated or reclaimed Btrfs bytes; null means incomplete/unsafe. Immediate root children only; nested checkouts are not exhaustively discovered. SQLite read-only WAL locks may update existing SHM bookkeeping; not byte immutability" })
}
