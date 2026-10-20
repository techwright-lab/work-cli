//! Private physical observations. No SQL, callbacks, secret-file reads or runtime authority.
use crate::capture_bridge::{EndedAt, Prepared, Refused, MAX_WIRE_BYTES};
use rustix::fs::{openat2, Mode, OFlags, ResolveFlags};
use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fmt,
    fs::File,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
type Result<T> = std::result::Result<T, Refused>;
#[derive(PartialEq, Eq)]
struct Stamp {
    dev: u64,
    ino: u64,
    len: u64,
    mode: u32,
    uid: u32,
    links: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}
fn stamp(f: &File) -> Result<Stamp> {
    let m = f.metadata().map_err(|_| Refused)?;
    Ok(Stamp {
        dev: m.dev(),
        ino: m.ino(),
        len: m.len(),
        mode: m.mode(),
        uid: m.uid(),
        links: m.nlink(),
        mtime: (m.mtime(), m.mtime_nsec()),
        ctime: (m.ctime(), m.ctime_nsec()),
    })
}
fn open(path: &Path, flags: OFlags) -> Result<File> {
    if !path.is_absolute()
        || path.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(Refused);
    }
    let root = File::open("/").map_err(|_| Refused)?;
    openat2(
        &root,
        path.strip_prefix("/").map_err(|_| Refused)?,
        flags
            | OFlags::CLOEXEC
            | if flags.contains(OFlags::PATH) {
                OFlags::empty()
            } else {
                OFlags::NONBLOCK
            },
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
    )
    .map(File::from)
    .map_err(|_| Refused)
}
fn regular(s: &Stamp, readonly: bool) -> Result<()> {
    if s.mode & 0o170000 != 0o100000
        || s.uid != rustix::process::geteuid().as_raw()
        || s.links != 1
        || !matches!(s.mode & 0o7777, 0o400 | 0o600)
        || (readonly && s.mode & 0o7777 != 0o400)
    {
        return Err(Refused);
    }
    Ok(())
}
/// Only metadata: O_PATH never reads or hashes a credential's contents.
pub(super) fn key_metadata(path: &Path) -> Result<()> {
    regular(&stamp(&open(path, OFlags::PATH)?)?, false)
}
pub(super) struct Directory {
    path: PathBuf,
    file: File,
    dev: u64,
    ino: u64,
}
impl Directory {
    pub(super) fn qualify(path: &Path) -> Result<Self> {
        let file = open(path, OFlags::RDONLY | OFlags::DIRECTORY)?;
        let s = stamp(&file)?;
        if s.uid != rustix::process::geteuid().as_raw() || s.mode & 0o7777 != 0o700 {
            return Err(Refused);
        }
        Ok(Self {
            path: path.into(),
            file,
            dev: s.dev,
            ino: s.ino,
        })
    }
    fn revalidate(&self) -> Result<()> {
        for file in [
            &self.file,
            &open(&self.path, OFlags::RDONLY | OFlags::DIRECTORY)?,
        ] {
            let s = stamp(file)?;
            if s.dev != self.dev
                || s.ino != self.ino
                || s.uid != rustix::process::geteuid().as_raw()
                || s.mode & 0o7777 != 0o700
            {
                return Err(Refused);
            }
        }
        Ok(())
    }
}
pub(super) struct Artifact {
    path: PathBuf,
    file: File,
    observed: Stamp,
    digest: [u8; 32],
}
impl Artifact {
    fn read(path: &Path, readonly: bool) -> Result<(Self, Vec<u8>)> {
        let mut file = open(path, OFlags::RDONLY)?;
        let before = stamp(&file)?;
        regular(&before, readonly)?;
        if before.len > MAX_WIRE_BYTES as u64 {
            return Err(Refused);
        }
        #[cfg(test)]
        tests::observe_read(path, &file, "before_read");
        let mut bytes = Vec::new();
        (&mut file)
            .take(MAX_WIRE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Refused)?;
        #[cfg(test)]
        tests::observe_read(path, &file, "after_read");
        if bytes.len() > MAX_WIRE_BYTES
            || bytes.len() as u64 != before.len
            || stamp(&file)? != before
        {
            return Err(Refused);
        }
        let digest = Sha256::digest(&bytes).into();
        let proof = Self {
            path: path.into(),
            file,
            observed: before,
            digest,
        };
        #[cfg(test)]
        tests::observe_read(path, &proof.file, "before_path");
        if stamp(&open(path, OFlags::PATH)?)? != proof.observed {
            return Err(Refused);
        }
        Ok((proof, bytes))
    }
    pub(super) fn revalidate(&self, readonly: bool) -> Result<()> {
        if stamp(&self.file)? != self.observed {
            return Err(Refused);
        }
        let (current, _) = Self::read(&self.path, readonly)?;
        if current.observed != self.observed || current.digest != self.digest {
            return Err(Refused);
        }
        Ok(())
    }
}
pub(super) struct Registry {
    artifact: Artifact,
    pub(super) key_env: String,
}
impl Registry {
    pub(super) fn qualify(path: &Path, pin: &str) -> Result<Self> {
        let (artifact, bytes) = Artifact::read(path, false)?;
        if format!("{:x}", Sha256::digest(&bytes)) != pin {
            return Err(Refused);
        }
        let value = unique(&bytes)?;
        let object = value.as_object().ok_or(Refused)?;
        let ingest = object
            .get("ingest")
            .map(|v| v.as_object().ok_or(Refused))
            .transpose()?;
        let key_env = match ingest.and_then(|o| o.get("key_env")) {
            Some(v) => v.as_str().ok_or(Refused)?,
            None => "DEVDIARY_INGEST_KEY",
        };
        credential_name(key_env)?;
        if let Some(url) = ingest.and_then(|o| o.get("url")) {
            if !url.is_string() {
                return Err(Refused);
            }
        }
        Ok(Self {
            artifact,
            key_env: key_env.into(),
        })
    }
    pub(super) fn revalidate(&self) -> Result<()> {
        self.artifact.revalidate(false)
    }
}
pub(super) fn credential_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 256
        || !name
            .bytes()
            .enumerate()
            .all(|(i, b)| b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit()))
        || matches!(
            name,
            "AGENT_ATTRIBUTION_CONTEXT"
                | "DEVDIARY_ATTRIBUTION_CONTEXT"
                | "DEVDIARY_CAPTURE_ID"
                | "GIT_AUTHOR_NAME"
                | "GIT_AUTHOR_EMAIL"
                | "GIT_COMMITTER_NAME"
                | "GIT_COMMITTER_EMAIL"
                | "XDG_RUNTIME_DIR"
                | "DBUS_SESSION_BUS_ADDRESS"
        )
    {
        return Err(Refused);
    }
    Ok(())
}
/// Passive nonsecret audit data. Never a live file/capture capability.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextArtifactObservation {
    device: u64,
    inode: u64,
    length: u64,
    sha256: [u8; 32],
    modified: (i64, i64),
    changed: (i64, i64),
}
impl ContextArtifactObservation {
    pub(crate) fn validate(&self) -> bool {
        self.length <= MAX_WIRE_BYTES as u64
    }
}
pub(super) struct Context {
    artifact: Artifact,
    directory: Directory,
    spec_digest: [u8; 32],
}
impl Context {
    pub(super) fn qualify(
        directory: Directory,
        prepared: &Prepared,
        spec: &crate::capture_journal::CaptureSpec,
    ) -> Result<Self> {
        let request = spec.begin_request();
        directory.revalidate()?;
        let path = directory.path.join(format!(
            "{}.context.json",
            prepared.binding().capture_id().as_str()
        ));
        if prepared.environment().context_path() != path {
            return Err(Refused);
        }
        let (artifact, bytes) = Artifact::read(&path, true)?;
        let value = unique(&bytes)?;
        let o = value.as_object().ok_or(Refused)?;
        let actor = o.get("actor").and_then(Value::as_object).ok_or(Refused)?;
        let run = o.get("run").and_then(Value::as_object).ok_or(Refused)?;
        for field in ["principal", "command"] {
            if o.get(field).is_some_and(|v| !v.is_object()) {
                return Err(Refused);
            }
        }
        let parent = run.get("parent_ref").filter(|v| !v.is_null());
        if o.get("schema_version").and_then(Value::as_str) != Some("1.0")
            || actor.get("ref").and_then(Value::as_str) != Some(&request.actor_ref)
            || run.get("ref").and_then(Value::as_str) != Some(&request.run_ref)
            || parent.map(|v| v.as_str().ok_or(Refused)).transpose()?
                != request.parent_run_ref.as_deref()
            || run.get("task_ref").and_then(Value::as_str)
                != request.task_refs.first().map(String::as_str)
            || o.get("working_directory").and_then(Value::as_str) != request.cwd.to_str()
            || o.get("execution_chain")
                != Some(&serde_json::to_value(&request.execution_chain).map_err(|_| Refused)?)
        {
            return Err(Refused);
        }
        EndedAt::parse(o.get("started_at").and_then(Value::as_str).ok_or(Refused)?)?;
        directory.revalidate()?;
        Ok(Self {
            artifact,
            directory,
            spec_digest: spec_digest(spec)?,
        })
    }
    pub(super) fn revalidate(&self) -> Result<()> {
        self.directory.revalidate()?;
        self.artifact.revalidate(true)?;
        self.directory.revalidate()
    }
    pub(crate) fn observation(
        &self,
        path: &Path,
        spec: &crate::capture_journal::CaptureSpec,
    ) -> Result<ContextArtifactObservation> {
        if self.artifact.path != path || self.spec_digest != spec_digest(spec)? {
            return Err(Refused);
        }
        let s = &self.artifact.observed;
        Ok(ContextArtifactObservation {
            device: s.dev,
            inode: s.ino,
            length: s.len,
            sha256: self.artifact.digest,
            modified: s.mtime,
            changed: s.ctime,
        })
    }
}
fn spec_digest(spec: &crate::capture_journal::CaptureSpec) -> Result<[u8; 32]> {
    Ok(Sha256::digest(serde_json::to_vec(spec).map_err(|_| Refused)?).into())
}
// Recursive unique-key JSON, including objects nested in legitimate chain arrays.
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("unique JSON")
            }
            fn visit_map<M: MapAccess<'de>>(
                self,
                mut m: M,
            ) -> std::result::Result<Unique, M::Error> {
                let mut keys = HashSet::new();
                let mut o = serde_json::Map::new();
                while let Some(k) = m.next_key::<String>()? {
                    if !keys.insert(k.clone()) {
                        return Err(de::Error::custom("duplicate"));
                    }
                    o.insert(k, m.next_value::<Unique>()?.0);
                }
                Ok(Unique(Value::Object(o)))
            }
            fn visit_seq<S: SeqAccess<'de>>(
                self,
                mut s: S,
            ) -> std::result::Result<Unique, S::Error> {
                let mut a = Vec::new();
                while let Some(v) = s.next_element::<Unique>()? {
                    a.push(v.0);
                }
                Ok(Unique(Value::Array(a)))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::String(v.into())))
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Bool(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Unique, E> {
                Ok(Unique(
                    serde_json::Number::from_f64(v)
                        .ok_or_else(|| de::Error::custom("number"))?
                        .into(),
                ))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
        }
        d.deserialize_any(V)
    }
}
#[cfg(test)]
#[path = "capture_artifacts_tests.rs"]
mod tests;
fn unique(bytes: &[u8]) -> Result<Value> {
    serde_json::from_slice::<Unique>(bytes)
        .map(|v| v.0)
        .map_err(|_| Refused)
}
