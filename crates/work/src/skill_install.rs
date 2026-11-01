//! Explicit native registration of embedded, versioned agent instructions.
//! No config loader, Git child, Python, authority access or implicit startup hook.
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env, fs,
    io::{self, Read, Write},
    os::unix::fs::{symlink, MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
};

type Result<T> = std::result::Result<T, String>;
const FILES: &[(&str, &str)] = &[
    (
        "skills/work-cli/SKILL.md",
        include_str!("../../../skills/work-cli/SKILL.md"),
    ),
    (
        "skills/work-cli/reference/setup.md",
        include_str!("../../../skills/work-cli/reference/setup.md"),
    ),
    (
        "docs/distribution.md",
        include_str!("../../../docs/distribution.md"),
    ),
];
fn error(message: &str) -> String {
    message.to_owned()
}
fn io<T>(result: io::Result<T>) -> Result<T> {
    result.map_err(|reason| {
        format!("skill installation I/O failed ({reason}); check current links before retrying")
    })
}
fn metadata(path: &Path) -> Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(meta) => Ok(Some(meta)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(error("cannot inspect skill installation path")),
    }
}
fn uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn directory(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(error("HOME and XDG_DATA_HOME must be absolute"));
    }
    let mut current = PathBuf::new();
    for part in path.components() {
        match part {
            Component::RootDir | Component::Normal(_) => current.push(part.as_os_str()),
            _ => return Err(error("noncanonical skill directory path")),
        }
        let meta = match metadata(&current)? {
            Some(meta) => meta,
            None => {
                let mut builder = fs::DirBuilder::new();
                std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
                io(builder.create(&current))?;
                io(fs::symlink_metadata(&current))?
            }
        };
        if !meta.is_dir() {
            return Err(error("skill directories cannot contain symlinks or files"));
        }
    }
    let meta = io(fs::symlink_metadata(path))?;
    if meta.uid() != uid() || meta.mode() & 0o022 != 0 {
        return Err(error(
            "skill directory must be owned and not group/world writable",
        ));
    }
    for name in [
        "store.sqlite",
        "authorities.sqlite",
        "initialization.json",
        "allocation.lock",
        "checkout-operations-v1",
    ] {
        if metadata(&path.join(name))?.is_some() {
            return Err(error(
                "keep skill installation separate from Work authority",
            ));
        }
    }
    Ok(())
}
fn sync(path: &Path) -> Result<()> {
    io(io(fs::File::open(path))?.sync_all())
}
fn lock(data: &Path) -> Result<fs::File> {
    let file = io(fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(data.join(".install.lock")))?;
    let meta = io(file.metadata())?;
    if !meta.is_file() || meta.uid() != uid() || meta.nlink() != 1 {
        return Err(error("invalid installer lock"));
    }
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| error("another installer is active"))?;
    Ok(file)
}
fn valid_current(target: &Path) -> bool {
    let Some(text) = target.to_str() else {
        return false;
    };
    let parts: Vec<_> = text.split('/').collect();
    parts.len() == 4
        && parts[0] == "skill-snapshots"
        && parts[2] == "skills"
        && parts[3] == "work-cli"
        && parts[1].len() == 64
        && parts[1]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn managed_link(path: &Path, expected: &Path) -> Result<()> {
    if let Some(meta) = metadata(path)? {
        if meta.uid() != uid()
            || !meta.file_type().is_symlink()
            || io(fs::read_link(path))? != expected
        {
            return Err(error(
                "existing unrelated skill target retained; resolve the conflict explicitly",
            ));
        }
    }
    Ok(())
}
fn atomic_link(path: &Path, target: &Path) -> Result<()> {
    let parent = path.parent().ok_or_else(|| error("missing skill parent"))?;
    let temporary = parent.join(format!(".work-skill-{}", uuid::Uuid::now_v7()));
    io(symlink(target, &temporary))?;
    let result = io(fs::rename(&temporary, path));
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result?;
    sync(parent)
}
fn snapshot_id() -> String {
    let mut hash = Sha256::new();
    hash.update(b"work.embedded-skill.v1\0");
    for (name, body) in FILES {
        hash.update((name.len() as u64).to_be_bytes());
        hash.update(name.as_bytes());
        hash.update((body.len() as u64).to_be_bytes());
        hash.update(body.as_bytes());
    }
    hash.finalize().iter().map(|b| format!("{b:02x}")).collect()
}
fn snapshot_files(root: &Path, dir: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) -> Result<()> {
    for item in io(fs::read_dir(dir))? {
        let path = io(item)?.path();
        let meta = io(fs::symlink_metadata(&path))?;
        if meta.uid() != uid() || meta.mode() & 0o022 != 0 {
            return Err(error("unsafe skill snapshot ownership or permissions"));
        }
        if meta.is_dir() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| error("invalid snapshot path"))?;
            if ![
                Path::new("skills"),
                Path::new("skills/work-cli"),
                Path::new("skills/work-cli/reference"),
                Path::new("docs"),
            ]
            .contains(&relative)
            {
                return Err(error("unknown skill snapshot directory"));
            }
            snapshot_files(root, &path, files)?;
        } else {
            if !meta.is_file()
                || meta.nlink() != 1
                || meta.len() > 1024 * 1024
                || files.len() >= FILES.len()
            {
                return Err(error("unsafe or oversized skill snapshot"));
            }
            let mut file = io(fs::OpenOptions::new()
                .read(true)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                .open(&path))?;
            let mut bytes = Vec::new();
            io((&mut file).take(1024 * 1024 + 1).read_to_end(&mut bytes))?;
            if bytes.len() > 1024 * 1024 {
                return Err(error("skill snapshot grew beyond limit"));
            }
            let relative = path
                .strip_prefix(root)
                .map_err(|_| error("invalid snapshot path"))?;
            files.insert(relative.to_path_buf(), bytes);
        }
    }
    Ok(())
}
fn snapshot(data: &Path) -> Result<PathBuf> {
    let snapshots = data.join("skill-snapshots");
    directory(&snapshots)?;
    let id = snapshot_id();
    let target = snapshots.join(&id);
    let expected: BTreeMap<_, _> = FILES
        .iter()
        .map(|(name, body)| (PathBuf::from(name), body.as_bytes().to_vec()))
        .collect();
    if let Some(meta) = metadata(&target)? {
        if !meta.is_dir() || meta.uid() != uid() || meta.mode() & 0o022 != 0 {
            return Err(error("unsafe cached skill snapshot"));
        }
        let mut actual = BTreeMap::new();
        snapshot_files(&target, &target, &mut actual)?;
        if actual != expected {
            return Err(error(
                "cached skill snapshot changed; refusing to replace it",
            ));
        }
    } else {
        let stage = io(tempfile::Builder::new()
            .prefix(".skill-")
            .tempdir_in(&snapshots))?;
        for (name, body) in FILES {
            let path = stage.path().join(name);
            let parent = path
                .parent()
                .ok_or_else(|| error("invalid embedded path"))?;
            directory(parent)?;
            let mut file = io(fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path))?;
            io(file.write_all(body.as_bytes()))?;
            io(file.sync_all())?;
        }
        for name in [
            "skills/work-cli/reference",
            "skills/work-cli",
            "skills",
            "docs",
            "",
        ] {
            sync(&stage.path().join(name))?;
        }
        io(fs::rename(stage.path(), &target))?;
        sync(&snapshots)?;
    }
    Ok(PathBuf::from("skill-snapshots")
        .join(id)
        .join("skills/work-cli"))
}

#[derive(Serialize)]
pub(crate) struct Report {
    skill: &'static str,
    version: &'static str,
    snapshot: PathBuf,
    registered: Vec<PathBuf>,
    authority_modified: bool,
    binary_changed: bool,
}
pub(crate) fn install(all: bool) -> Result<Report> {
    let home = PathBuf::from(
        env::var_os("HOME").ok_or_else(|| error("HOME is required for agent discovery"))?,
    );
    if !home.is_absolute() {
        return Err(error("HOME must be absolute"));
    }
    let data_home = env::var_os("XDG_DATA_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".local/share"));
    if !data_home.is_absolute() {
        return Err(error("XDG_DATA_HOME must be absolute"));
    }
    if home.to_str().is_none() || data_home.to_str().is_none() {
        return Err(error(
            "agent discovery requires UTF-8 HOME and XDG_DATA_HOME paths",
        ));
    }
    let data = data_home.join("work-cli");
    directory(&data)?;
    let _lock = lock(&data)?;
    let current = data.join("skill-current");
    if let Some(meta) = metadata(&current)? {
        if meta.uid() != uid()
            || !meta.file_type().is_symlink()
            || !valid_current(&io(fs::read_link(&current))?)
        {
            return Err(error("unmanaged active skill pointer retained"));
        }
    }
    let agents: &[&str] = if all {
        &[".agents", ".claude", ".codex"]
    } else {
        &[".agents"]
    };
    let mut targets = Vec::new();
    // Preflight every target before publishing or replacing any skill link.
    for agent in agents {
        let root = home.join(agent).join("skills");
        directory(&root)?;
        let target = root.join("work-cli");
        managed_link(&target, &current)?;
        targets.push(target);
    }
    let relative = snapshot(&data)?;
    atomic_link(&current, &relative)?;
    for target in &targets {
        managed_link(target, &current)?;
        if metadata(target)?.is_none() {
            // Creation itself is atomic and must not replace a target that
            // appeared after preflight (another installer can use a different
            // data directory and therefore hold a different installer lock).
            io(symlink(&current, target))?;
            sync(
                target
                    .parent()
                    .ok_or_else(|| error("missing discovery parent"))?,
            )?;
        }
    }
    Ok(Report {
        skill: "work-cli",
        version: env!("CARGO_PKG_VERSION"),
        snapshot: relative,
        registered: targets,
        authority_modified: false,
        binary_changed: false,
    })
}
