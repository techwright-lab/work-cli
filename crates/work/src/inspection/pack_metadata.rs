//! Read-only validation of native auxiliary pack metadata against retained bytes.
//! Formats: git/git v2.56.0 Documentation/gitformat-pack.adoc and server-info.c.
//! These files are never object/ownership authority and never waive native fsck.
use super::{hex, Budget, IncompleteReason, ObjectFormat};
use std::collections::BTreeSet;

type Result<T> = std::result::Result<T, IncompleteReason>;
const INVALID: IncompleteReason = IncompleteReason::InvalidObject;

fn word(bytes: &[u8], at: usize) -> Result<u32> {
    let end = at.checked_add(4).ok_or(INVALID)?;
    Ok(u32::from_be_bytes(
        bytes
            .get(at..end)
            .ok_or(INVALID)?
            .try_into()
            .map_err(|_| INVALID)?,
    ))
}
fn end_of(base: usize, count: usize, width: usize) -> Result<usize> {
    base.checked_add(count.checked_mul(width).ok_or(INVALID)?)
        .ok_or(INVALID)
}
fn checked_body(bytes: &[u8], format: ObjectFormat) -> Result<&[u8]> {
    let end = bytes.len().checked_sub(format.width()).ok_or(INVALID)?;
    if format.hash(&bytes[..end]) != bytes[end..] {
        return Err(INVALID);
    }
    Ok(&bytes[..end])
}

/// RIDX v1 contains a permutation of index positions in increasing pack-offset
/// order. Validate the actual mapping, not merely header/checksum/permutation.
pub(super) fn reverse_index(
    id: &[u8],
    pack: &[u8],
    index: &[u8],
    reverse: &[u8],
    format: ObjectFormat,
    budget: &mut Budget,
) -> Result<()> {
    budget.check()?;
    let width = format.width();
    let pack_body = checked_body(pack, format)?;
    if pack_body.get(..4) != Some(b"PACK") || !matches!(word(pack_body, 4)?, 2 | 3) {
        return Err(INVALID);
    }
    let count = word(pack_body, 8)? as usize;
    let pack_hash = &pack[pack_body.len()..];
    if hex(pack_hash).as_bytes() != id {
        return Err(INVALID);
    }
    let index_body = checked_body(index, format)?;
    let index_end = index_body.len().checked_sub(width).ok_or(INVALID)?;
    if &index_body[index_end..] != pack_hash {
        return Err(INVALID);
    }
    let v2 = index_body.starts_with(b"\xfftOc");
    let fanout = if v2 {
        if word(index_body, 4)? != 2 {
            return Err(INVALID);
        }
        8
    } else {
        0
    };
    let table = fanout + 1024;
    if word(index_body, table - 4)? as usize != count {
        return Err(INVALID);
    }
    let mut previous_count = 0;
    for bucket in 0..256 {
        let current = word(index_body, fanout + bucket * 4)? as usize;
        if current < previous_count || current > count {
            return Err(INVALID);
        }
        previous_count = current;
    }
    let offsets_at = if v2 {
        end_of(table, count, width + 4)?
    } else {
        table
    };
    let offsets_end = if v2 {
        end_of(offsets_at, count, 4)?
    } else {
        end_of(table, count, width + 4)?
    };
    let extra = index_end.checked_sub(offsets_end).ok_or(INVALID)?;
    if (!v2 && extra != 0) || extra % 8 != 0 || extra / 8 > count {
        return Err(INVALID);
    }
    // Length checks precede allocations; all input bytes already share the
    // retained manifest's file/read limits. No unbounded count from a header.
    let mut large_used = vec![false; extra / 8];
    let mut offsets = Vec::with_capacity(count);
    let mut prior_oid: Option<&[u8]> = None;
    for i in 0..count {
        if i % 1024 == 0 {
            budget.check()?;
        }
        let oid_at = if v2 {
            table + i * width
        } else {
            table + i * (width + 4) + 4
        };
        let object = index_body.get(oid_at..oid_at + width).ok_or(INVALID)?;
        if prior_oid.is_some_and(|prior| prior >= object) {
            return Err(INVALID);
        }
        prior_oid = Some(object);
        let bucket = usize::from(object[0]);
        let upper = word(index_body, fanout + bucket * 4)? as usize;
        let lower = if bucket == 0 {
            0
        } else {
            word(index_body, fanout + (bucket - 1) * 4)? as usize
        };
        if i < lower || i >= upper {
            return Err(INVALID);
        }
        let at = if v2 {
            offsets_at + i * 4
        } else {
            table + i * (width + 4)
        };
        let offset = word(index_body, at)?;
        let offset = if v2 && offset & 0x8000_0000 != 0 {
            let large = (offset & 0x7fff_ffff) as usize;
            let used = large_used.get_mut(large).ok_or(INVALID)?;
            if *used {
                return Err(INVALID);
            }
            *used = true;
            let at = offsets_end + large * 8;
            u64::from_be_bytes(
                index_body
                    .get(at..at + 8)
                    .ok_or(INVALID)?
                    .try_into()
                    .map_err(|_| INVALID)?,
            )
        } else {
            u64::from(offset)
        };
        if offset < 12 || offset >= pack_body.len() as u64 {
            return Err(INVALID);
        }
        offsets.push(offset);
    }
    if large_used.iter().any(|used| !used) {
        return Err(INVALID);
    }
    let reverse_body = checked_body(reverse, format)?;
    let reverse_end = end_of(12, count, 4)?;
    if reverse_body.len() != reverse_end.checked_add(width).ok_or(INVALID)?
        || reverse_body.get(..4) != Some(b"RIDX")
        || word(reverse_body, 4)? != 1
        || word(reverse_body, 8)?
            != match format {
                ObjectFormat::Sha1 => 1,
                ObjectFormat::Sha256 => 2,
            }
        || &reverse_body[reverse_end..] != pack_hash
    {
        return Err(INVALID);
    }
    let mut previous = 11;
    for i in 0..count {
        if i % 1024 == 0 {
            budget.check()?;
        }
        let position = word(reverse_body, 12 + i * 4)? as usize;
        let offset = *offsets.get(position).ok_or(INVALID)?;
        // Strictly increasing offsets also prove positions are unique, hence
        // count positions in a count-sized index form a complete permutation.
        if offset <= previous || (i == 0 && offset != 12) {
            return Err(INVALID);
        }
        previous = offset;
    }
    budget.check()
}

/// Native update-server-info emits `P pack-<id>.pack\n` rows and a final blank
/// line. Accept any order, but no duplicates, omissions, stale names or paths.
pub(super) fn pack_list(bytes: &[u8], packs: &BTreeSet<Vec<u8>>) -> Result<()> {
    let mut listed = BTreeSet::new();
    if bytes != b"\n" {
        let body = bytes.strip_suffix(b"\n\n").ok_or(INVALID)?;
        if body.is_empty() {
            return Err(INVALID);
        }
        for row in body.split(|c| *c == b'\n') {
            let name = row.strip_prefix(b"P ").ok_or(INVALID)?;
            if !packs.contains(name) || !listed.insert(name.to_vec()) {
                return Err(INVALID);
            }
        }
    }
    if &listed != packs {
        return Err(INVALID);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inspection::{filesystem, fixture, object_storage};
    use std::{fs, path::PathBuf};

    struct Native {
        _temp: tempfile::TempDir,
        repo: PathBuf,
        path: PathBuf,
        id: Vec<u8>,
        pack: Vec<u8>,
        index: Vec<u8>,
        reverse: Vec<u8>,
        format: ObjectFormat,
    }
    impl Native {
        fn new(format: ObjectFormat) -> Self {
            let temp = tempfile::tempdir().unwrap();
            let repo = temp.path().to_path_buf();
            let hash = match format {
                ObjectFormat::Sha1 => "sha1",
                ObjectFormat::Sha256 => "sha256",
            };
            fixture::git(
                &repo,
                &[
                    "init".as_ref(),
                    "-b".as_ref(),
                    "main".as_ref(),
                    format!("--object-format={hash}").as_ref(),
                ],
            );
            fs::write(repo.join("data"), b"native pack fixture\n").unwrap();
            fixture::git(&repo, &["add".as_ref(), "data".as_ref()]);
            fixture::git(
                &repo,
                &["commit".as_ref(), "-m".as_ref(), "initial".as_ref()],
            );
            fixture::git(
                &repo,
                &[
                    "-c".as_ref(),
                    "pack.writeReverseIndex=true".as_ref(),
                    "repack".as_ref(),
                    "-ad".as_ref(),
                ],
            );
            let path = fs::read_dir(repo.join(".git/objects/pack"))
                .unwrap()
                .map(|e| e.unwrap().path())
                .find(|p| p.extension().is_some_and(|e| e == "pack"))
                .unwrap();
            let id = path
                .file_stem()
                .unwrap()
                .to_str()
                .unwrap()
                .strip_prefix("pack-")
                .unwrap()
                .as_bytes()
                .to_vec();
            Self {
                pack: fs::read(&path).unwrap(),
                index: fs::read(path.with_extension("idx")).unwrap(),
                reverse: fs::read(path.with_extension("rev")).unwrap(),
                path,
                id,
                repo,
                _temp: temp,
                format,
            }
        }
        fn validate(&self, pack: &[u8], index: &[u8], reverse: &[u8]) -> Result<()> {
            reverse_index(
                &self.id,
                pack,
                index,
                reverse,
                self.format,
                &mut Budget::new(),
            )
        }
    }
    fn seal(bytes: &mut [u8], format: ObjectFormat) {
        let end = bytes.len() - format.width();
        let hash = format.hash(&bytes[..end]);
        bytes[end..].copy_from_slice(&hash);
    }

    #[test]
    fn native_reverse_index_versions_and_large_offsets() {
        for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
            let f = Native::new(format);
            f.validate(&f.pack, &f.index, &f.reverse).unwrap();
            for version in ["--index-version=1", "--index-version=2,0"] {
                fixture::git(
                    &f.repo,
                    &[
                        "index-pack".as_ref(),
                        version.as_ref(),
                        "--rev-index".as_ref(),
                        f.path.as_os_str(),
                    ],
                );
                let index = fs::read(f.path.with_extension("idx")).unwrap();
                let reverse = fs::read(f.path.with_extension("rev")).unwrap();
                f.validate(&f.pack, &index, &reverse).unwrap();
                if version.ends_with(",0") {
                    let count = word(&index, 8 + 1020).unwrap() as usize;
                    let at = 8 + 1024 + count * (format.width() + 4);
                    assert_ne!(word(&index, at).unwrap() & 0x8000_0000, 0);
                    let mut bad = index.clone();
                    bad[at..at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
                    seal(&mut bad, format);
                    assert!(f.validate(&f.pack, &bad, &reverse).is_err());
                }
            }
        }
    }

    #[test]
    fn reverse_index_corruption_and_rechecksummed_mappings_hold() {
        for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
            let f = Native::new(format);
            let count = word(&f.pack, 8).unwrap();
            assert!(count > 1);
            for case in [
                "magic",
                "version",
                "hash",
                "pack-binding",
                "range",
                "duplicate",
                "order",
                "checksum",
                "trailing",
            ] {
                let mut bad = f.reverse.clone();
                match case {
                    "magic" => bad[0] ^= 1,
                    "version" => bad[4..8].copy_from_slice(&2u32.to_be_bytes()),
                    "hash" => bad[8..12].copy_from_slice(&0u32.to_be_bytes()),
                    "pack-binding" => bad[12 + count as usize * 4] ^= 1,
                    "range" => bad[12..16].copy_from_slice(&count.to_be_bytes()),
                    "duplicate" => {
                        let first = bad[12..16].to_vec();
                        bad[16..20].copy_from_slice(&first);
                    }
                    "order" => {
                        for i in 0..4 {
                            bad.swap(12 + i, 16 + i);
                        }
                    }
                    "checksum" => {
                        let end = bad.len() - 1;
                        bad[end] ^= 1;
                    }
                    "trailing" => bad.insert(bad.len() - format.width(), 0),
                    _ => unreachable!(),
                }
                if case != "checksum" {
                    seal(&mut bad, format);
                }
                assert!(
                    f.validate(&f.pack, &f.index, &bad).is_err(),
                    "{format:?}/{case}"
                );
            }
            // Rehashed index evidence still must bind counts, names and offsets.
            for at in [
                8usize,
                8 + 1020,
                8 + 1024,
                8 + 1024 + count as usize * (format.width() + 4),
            ] {
                let mut bad = f.index.clone();
                bad[at..at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
                seal(&mut bad, format);
                assert!(f.validate(&f.pack, &bad, &f.reverse).is_err());
            }
            let mut bad_pack = f.pack.clone();
            bad_pack[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
            seal(&mut bad_pack, format);
            assert!(f.validate(&bad_pack, &f.index, &f.reverse).is_err());
            for length in 0..f.reverse.len() {
                assert!(f.validate(&f.pack, &f.index, &f.reverse[..length]).is_err());
            }
            for length in [0, 4, 8, 12, 1024, f.index.len() - 1] {
                assert!(f.validate(&f.pack, &f.index[..length], &f.reverse).is_err());
            }
            assert!(reverse_index(
                b"wrong-name",
                &f.pack,
                &f.index,
                &f.reverse,
                format,
                &mut Budget::new()
            )
            .is_err());
        }
    }

    #[test]
    fn native_pack_list_requires_exact_membership() {
        let a = b"pack-1111111111111111111111111111111111111111.pack".to_vec();
        let b = b"pack-2222222222222222222222222222222222222222.pack".to_vec();
        let packs = BTreeSet::from([a.clone(), b.clone()]);
        let row = |name: &[u8]| format!("P {}\n", std::str::from_utf8(name).unwrap());
        assert!(pack_list(format!("{}{}\n", row(&b), row(&a)).as_bytes(), &packs).is_ok());
        for body in [
            String::new(),
            "\n".into(),
            format!("{}\n", row(&a)),
            format!("{}{}{}\n", row(&a), row(&a), row(&b)),
            format!("{}{}", row(&a), row(&b)),
            "P ../foreign.pack\n\n".into(),
        ] {
            assert!(pack_list(body.as_bytes(), &packs).is_err(), "{body:?}");
        }
        assert!(pack_list(b"\n", &BTreeSet::new()).is_ok());
    }

    #[test]
    fn empty_graph_directory_is_retained_not_ignored() {
        let f = Native::new(ObjectFormat::Sha1);
        let common = f.repo.join(".git");
        let graphs = common.join("objects/info/commit-graphs");
        fs::create_dir(&graphs).unwrap();
        let mut budget = Budget::new();
        let mut manifest = filesystem::Manifest::new(&common, &mut budget).unwrap();
        object_storage(&mut manifest, f.format, &mut budget).unwrap();
        fs::rename(&graphs, f.repo.join("old-graphs")).unwrap();
        fs::create_dir(&graphs).unwrap();
        assert!(matches!(
            manifest.recheck(&mut budget),
            Err(IncompleteReason::Changed)
        ));
    }

    #[test]
    fn auxiliary_files_are_retained_and_replacement_invalidates_evidence() {
        let f = Native::new(ObjectFormat::Sha1);
        for relative in [
            format!(
                "objects/pack/{}.rev",
                f.path.file_stem().unwrap().to_str().unwrap()
            ),
            "objects/info/packs".into(),
        ] {
            let common = f.repo.join(".git");
            let mut budget = Budget::new();
            let mut manifest = filesystem::Manifest::new(&common, &mut budget).unwrap();
            object_storage(&mut manifest, f.format, &mut budget).unwrap();
            assert!(manifest
                .object_files()
                .contains(&relative.as_bytes().to_vec()));
            let path = common.join(&relative);
            let replacement = f.repo.join("replacement");
            fs::write(&replacement, fs::read(&path).unwrap()).unwrap();
            fs::rename(replacement, &path).unwrap();
            assert!(matches!(
                manifest.recheck(&mut budget),
                Err(IncompleteReason::Changed)
            ));
        }
    }
}
