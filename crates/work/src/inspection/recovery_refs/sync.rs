//! Descriptor-bound synchronization and create-only CAS. OS fsync ACK only.
use super::super::{filesystem, git, oid, valid_ref, Budget, IncompleteReason, ObjectFormat};
use super::storage::PlanEntry;
use std::{collections::BTreeSet, path::Path};

type Held<T> = Result<T, &'static str>;

pub(super) fn persistent_manifest(manifest: &filesystem::Manifest) -> Held<()> {
    manifest
        .persistent_fs()
        .map_err(|_| "nonpersistent_filesystem")
}

fn checked<T>(value: Result<T, IncompleteReason>) -> Held<T> {
    value.map_err(|_| "sync_unknown")
}

pub(super) fn sync_objects(common: &filesystem::Manifest, b: &mut Budget) -> Held<()> {
    checked(common.sync_prefix(b"objects", b))?;
    Ok(())
}

pub(super) fn sync_refs(
    common: &filesystem::Manifest,
    created: &[String],
    packed: bool,
    b: &mut Budget,
) -> Held<()> {
    if packed {
        checked(common.sync_path(b"packed-refs", false, b))?;
    }
    for name in created {
        checked(common.sync_path(name.as_bytes(), false, b))?;
    }
    for ancestor in created.iter().flat_map(|name| ancestor_dirs(name)) {
        checked(common.sync_path(&ancestor, true, b))?;
    }
    Ok(())
}

pub(super) fn zeros(format: ObjectFormat) -> String {
    "0".repeat(format.width() * 2)
}

pub(super) fn create_missing(
    cwd: &Path,
    entry: &PlanEntry,
    format: ObjectFormat,
    b: &mut Budget,
) -> Held<bool> {
    if !valid_ref(entry.reference.as_bytes()) || !entry.reference.starts_with("refs/work-recovery/")
    {
        return Err("recovery_ref_unknown");
    }
    checked(oid(entry.oid.as_bytes(), format))?;
    let old = zeros(format);
    if entry.oid.len() != old.len() {
        return Err("oid_width_unknown");
    }
    let output = git(
        Some(cwd),
        &[
            "-c",
            "core.logAllRefUpdates=false",
            "update-ref",
            "--no-deref",
            "--",
            &entry.reference,
            &entry.oid,
            &old,
        ],
        b"",
        b,
    )
    .map_err(|_| "cas_unknown")?;
    if output.code != 0 {
        return Err("cas_held");
    }
    if !output.stdout.is_empty() {
        return Err("cas_protocol_unknown");
    }
    Ok(true)
}

pub(super) fn recovery_log_absent(
    common: &mut filesystem::Manifest,
    reference: &str,
    b: &mut Budget,
) -> Held<()> {
    let mut path = b"logs/".to_vec();
    path.extend(reference.as_bytes());
    match common.absent(&path, b) {
        Ok(()) => Ok(()),
        Err(_) => Err("recovery_reflog_present"),
    }
}

pub(super) fn planned_names(plan: &[PlanEntry]) -> BTreeSet<Vec<u8>> {
    plan.iter()
        .map(|e| e.reference.as_bytes().to_vec())
        .collect()
}

pub(super) fn ancestor_dirs(reference: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let bytes = reference.as_bytes();
    let mut i = 0;
    while let Some(rel) = bytes[i..].iter().position(|c| *c == b'/') {
        i += rel;
        out.push(bytes[..i].to_vec());
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeros_match_object_format_width() {
        assert_eq!(zeros(ObjectFormat::Sha1).len(), 40);
        assert_eq!(zeros(ObjectFormat::Sha256).len(), 64);
        assert!(zeros(ObjectFormat::Sha1).chars().all(|c| c == '0'));
    }

    #[test]
    fn ancestor_dirs_are_prefix_chain() {
        let dirs = ancestor_dirs("refs/work-recovery/x/sha1/aa");
        assert_eq!(
            dirs,
            [
                b"refs".to_vec(),
                b"refs/work-recovery".to_vec(),
                b"refs/work-recovery/x".to_vec(),
                b"refs/work-recovery/x/sha1".to_vec()
            ]
        );
    }
}
