//! Bounded commit-graph envelope and chain validation, followed by native
//! read-only semantic verification. Graphs are disabled for ordinary Git proof.
//! Format: git/git v2.56.0 Documentation/gitformat-commit-graph.adoc.
use super::{
    filesystem, git_success, hex, oid, Budget, IncompleteReason, ObjectFormat, MAX_DEPTH,
    MAX_ENTRIES,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
type Result<T> = std::result::Result<T, IncompleteReason>;
const INVALID: IncompleteReason = IncompleteReason::InvalidObject;
const NONE: u32 = 0x7000_0000;
fn u32_at(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(
        bytes
            .get(at..at.checked_add(4).ok_or(INVALID)?)
            .ok_or(INVALID)?
            .try_into()
            .map_err(|_| INVALID)?,
    ))
}
fn u64_at(bytes: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_be_bytes(
        bytes
            .get(at..at.checked_add(8).ok_or(INVALID)?)
            .ok_or(INVALID)?
            .try_into()
            .map_err(|_| INVALID)?,
    ))
}

fn graph(
    bytes: &[u8],
    bases: &[Vec<u8>],
    base_count: usize,
    format: ObjectFormat,
    seen: &mut BTreeSet<Vec<u8>>,
    b: &mut Budget,
) -> Result<Vec<u8>> {
    b.check()?;
    let width = format.width();
    let end = bytes.len().checked_sub(width).ok_or(INVALID)?;
    if bytes.len() < 8 + width
        || bytes.get(..4) != Some(b"CGPH")
        || bytes[4] != 1
        || bytes[5]
            != match format {
                ObjectFormat::Sha1 => 1,
                ObjectFormat::Sha256 => 2,
            }
        || usize::from(bytes[7]) != bases.len()
        || format.hash(&bytes[..end]) != bytes[end..]
    {
        return Err(INVALID);
    }
    let count = usize::from(bytes[6]);
    if count == 0 || count > 7 {
        return Err(INVALID);
    }
    let table_end = 8 + (count + 1) * 12;
    if table_end > end {
        return Err(INVALID);
    }
    let mut chunks = BTreeMap::new();
    let mut start = usize::try_from(u64_at(bytes, 12)?).map_err(|_| INVALID)?;
    if start != table_end {
        return Err(INVALID);
    }
    for i in 0..count {
        let id = bytes.get(8 + i * 12..12 + i * 12).ok_or(INVALID)?;
        if ![
            b"OIDF".as_slice(),
            b"OIDL",
            b"CDAT",
            b"GDA2",
            b"GDO2",
            b"EDGE",
            b"BASE",
        ]
        .contains(&id)
        {
            // Bloom and unknown extensions are not silently trusted/ignored.
            return Err(IncompleteReason::UnsupportedGit);
        }
        let next = usize::try_from(u64_at(bytes, 12 + (i + 1) * 12)?).map_err(|_| INVALID)?;
        if next < start
            || next > end
            || start % 4 != 0
            || chunks
                .insert(id, bytes.get(start..next).ok_or(INVALID)?)
                .is_some()
        {
            return Err(INVALID);
        }
        start = next;
    }
    if start != end || bytes.get(8 + count * 12..12 + count * 12) != Some(b"\0\0\0\0") {
        return Err(INVALID);
    }
    let chunk = |id: &[u8]| chunks.get(id).copied().ok_or(INVALID);
    let fanout = chunk(b"OIDF")?;
    if fanout.len() != 1024 {
        return Err(INVALID);
    }
    let n = u32_at(fanout, 1020)? as usize;
    let total = base_count.checked_add(n).ok_or(INVALID)?;
    if total > MAX_ENTRIES as usize {
        return Err(IncompleteReason::EntryBudget);
    }
    let ids = chunk(b"OIDL")?;
    let data = chunk(b"CDAT")?;
    if ids.len() != n * width || data.len() != n * (width + 16) {
        return Err(INVALID);
    }
    let mut prior_count = 0;
    for bucket in 0..256 {
        let value = u32_at(fanout, bucket * 4)? as usize;
        if value < prior_count || value > n {
            return Err(INVALID);
        }
        prior_count = value;
    }
    let mut prior_id: Option<&[u8]> = None;
    for (i, id) in ids.chunks_exact(width).enumerate() {
        b.check()?;
        if prior_id.is_some_and(|prior| prior >= id) || !seen.insert(id.to_vec()) {
            return Err(INVALID);
        }
        prior_id = Some(id);
        let bucket = usize::from(id[0]);
        let lower = if bucket == 0 {
            0
        } else {
            u32_at(fanout, (bucket - 1) * 4)? as usize
        };
        if i < lower || i >= u32_at(fanout, bucket * 4)? as usize {
            return Err(INVALID);
        }
    }
    let edge = chunks.get(b"EDGE".as_slice()).copied().unwrap_or_default();
    if edge.len() % 4 != 0 {
        return Err(INVALID);
    }
    let parent = |p: u32, position: usize| {
        if p as usize >= total || p as usize == position {
            Err(INVALID)
        } else {
            Ok(())
        }
    };
    // Linear bounded validation: every extra-edge entry is a valid parent and
    // every referenced suffix has a terminating marker. No quadratic scans.
    let mut last_terminator = None;
    for i in 0..edge.len() / 4 {
        if i % 1024 == 0 {
            b.check()?;
        }
        let value = u32_at(edge, i * 4)?;
        if (value & 0x7fff_ffff) as usize >= total {
            return Err(INVALID);
        }
        if value & 0x8000_0000 != 0 {
            last_terminator = Some(i);
        }
    }
    for i in 0..n {
        b.check()?;
        let at = i * (width + 16) + width;
        let first = u32_at(data, at)?;
        let second = u32_at(data, at + 4)?;
        if first != NONE {
            parent(first, base_count + i)?;
        }
        if first == NONE && second != NONE {
            return Err(INVALID);
        }
        if second & 0x8000_0000 != 0 {
            let index = (second & 0x7fff_ffff) as usize;
            if last_terminator.is_none_or(|last| index > last) {
                return Err(INVALID);
            }
        } else if second != NONE {
            parent(second, base_count + i)?;
        }
    }
    match chunks.get(b"BASE".as_slice()) {
        Some(bytes)
            if bytes.len() == bases.len() * width
                && bytes
                    .chunks_exact(width)
                    .eq(bases.iter().map(Vec::as_slice)) => {}
        None if bases.is_empty() => (),
        _ => return Err(INVALID),
    }
    let overflow = chunks.get(b"GDO2".as_slice()).copied().unwrap_or_default();
    if overflow.len() % 8 != 0 {
        return Err(INVALID);
    }
    match chunks.get(b"GDA2".as_slice()) {
        Some(generation) if generation.len() == n * 4 => {
            for i in 0..n {
                let value = u32_at(generation, i * 4)?;
                if value & 0x8000_0000 != 0 && (value & 0x7fff_ffff) as usize >= overflow.len() / 8
                {
                    return Err(INVALID);
                }
            }
        }
        None if overflow.is_empty() => (),
        _ => return Err(INVALID),
    }
    Ok(bytes[end..].to_vec())
}

/// All graph paths come from this exact retained info-directory listing. No
/// filename supplied by a chain file is opened before canonical OID validation.
pub(super) fn capture(
    m: &mut filesystem::Manifest,
    names: &[Vec<u8>],
    format: ObjectFormat,
    b: &mut Budget,
) -> Result<bool> {
    let single = names.iter().any(|n| n == b"commit-graph");
    let split = names.iter().any(|n| n == b"commit-graphs");
    let mut hashes = Vec::new();
    let mut seen = BTreeSet::new();
    if single {
        graph(
            &m.required(b"objects/info/commit-graph", b)?,
            &[],
            0,
            format,
            &mut seen,
            b,
        )?;
    }
    if split {
        let files = m.list(b"objects/info/commit-graphs", b)?;
        if files.is_empty() {
            return Ok(single);
        }
        if single {
            return Err(IncompleteReason::UnsupportedGit);
        }
        let chain = m.required(b"objects/info/commit-graphs/commit-graph-chain", b)?;
        let body = chain.strip_suffix(b"\n").ok_or(INVALID)?;
        if body.is_empty() {
            return Err(INVALID);
        }
        let mut expected = BTreeSet::from([b"commit-graph-chain".to_vec()]);
        for id in body.split(|c| *c == b'\n') {
            if hashes.len() >= MAX_DEPTH {
                return Err(IncompleteReason::DepthBudget);
            }
            oid(id, format)?;
            let name = format!(
                "graph-{}.graph",
                std::str::from_utf8(id).map_err(|_| INVALID)?
            )
            .into_bytes();
            if !expected.insert(name.clone()) {
                return Err(INVALID);
            }
            let mut path = b"objects/info/commit-graphs/".to_vec();
            path.extend(&name);
            let bytes = m.required(&path, b)?;
            let count = seen.len();
            let hash = graph(&bytes, &hashes, count, format, &mut seen, b)?;
            if hex(&hash).as_bytes() != id {
                return Err(INVALID);
            }
            hashes.push(hash);
        }
        if files.into_iter().collect::<BTreeSet<_>>() != expected {
            return Err(INVALID);
        }
    }
    Ok(single || !hashes.is_empty())
}

pub(super) fn verify(common: &Path, native_input: u64, b: &mut Budget) -> Result<()> {
    // Match existing proof commands: reserve the retained object/admin input
    // envelope before native work; this is conservative accounting, not a
    // measurement or kernel-enforced bound on Git's internal reads.
    b.reserve(native_input)?;
    b.counters.native_input_reserved_bytes += native_input;
    let path = common.to_str().ok_or(IncompleteReason::InvalidPath)?;
    // No --shallow: verify every chain layer against native commit objects.
    // Explicit verify loads graph files even when core.commitGraph is false.
    // Source-audited builtin verify does not write, repair or expire graph data.
    git_success(
        Some(common),
        &["--git-dir", path, "commit-graph", "verify", "--no-progress"],
        b"",
        b,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inspection::fixture;
    use std::fs;

    #[test]
    fn native_verification_reserves_input_before_any_child() {
        let mut b = Budget::new();
        assert_eq!(
            verify(
                Path::new("/not-opened"),
                super::super::MAX_CHARGED_BYTES + 1,
                &mut b
            ),
            Err(IncompleteReason::ReadBudget)
        );
        assert_eq!(b.counters.child_launches, 0);
    }

    #[test]
    fn ordinary_git_proofs_disable_commit_graph_acceleration() {
        let command = crate::inspection::git_command(None);
        let args: Vec<_> = command.get_args().collect();
        assert!(args
            .windows(2)
            .any(|pair| pair == ["-c", "core.commitGraph=false"]));
    }

    #[test]
    fn native_chain_rejects_missing_duplicate_unknown_and_replaced_files() {
        for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
            let temp = tempfile::tempdir().unwrap();
            let repo = temp.path();
            let hash = match format {
                ObjectFormat::Sha1 => "sha1",
                ObjectFormat::Sha256 => "sha256",
            };
            fixture::git(
                repo,
                &[
                    "init".as_ref(),
                    "-b".as_ref(),
                    "main".as_ref(),
                    format!("--object-format={hash}").as_ref(),
                ],
            );
            for message in ["first", "second"] {
                fixture::git(
                    repo,
                    &[
                        "commit".as_ref(),
                        "--allow-empty".as_ref(),
                        "-m".as_ref(),
                        message.as_ref(),
                    ],
                );
                fixture::git(
                    repo,
                    &[
                        "commit-graph".as_ref(),
                        "write".as_ref(),
                        "--reachable".as_ref(),
                        "--split=no-merge".as_ref(),
                    ],
                );
            }
            let common = repo.join(".git");
            let dir = common.join("objects/info/commit-graphs");
            let chain = dir.join("commit-graph-chain");
            let bytes = fs::read(&chain).unwrap();
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&chain, fs::Permissions::from_mode(0o600)).unwrap();
            let ids: Vec<_> = bytes
                .split(|c| *c == b'\n')
                .filter(|r| !r.is_empty())
                .collect();
            assert_eq!(ids.len(), 2);
            let graph_path = dir.join(format!(
                "graph-{}.graph",
                std::str::from_utf8(ids[1]).unwrap()
            ));
            let graph_bytes = fs::read(&graph_path).unwrap();
            let check = || {
                let mut b = Budget::new();
                let mut m = filesystem::Manifest::new(&common, &mut b).unwrap();
                let names = m.list(b"objects/info", &mut b).unwrap();
                capture(&mut m, &names, format, &mut b)
            };
            assert_eq!(check(), Ok(true));
            for case in [
                "duplicate",
                "missing",
                "traversal",
                "unknown",
                "symlink",
                "base-order",
                "simultaneous",
            ] {
                match case {
                    "duplicate" => {
                        fs::write(&chain, [ids[0], b"\n", ids[0], b"\n"].concat()).unwrap()
                    }
                    "missing" => fs::rename(&graph_path, repo.join("saved.graph")).unwrap(),
                    "traversal" => fs::write(&chain, b"../../foreign\n").unwrap(),
                    "unknown" => fs::write(dir.join("unknown"), b"unrecognized").unwrap(),
                    "symlink" => {
                        fs::rename(&graph_path, repo.join("saved.graph")).unwrap();
                        std::os::unix::fs::symlink(repo.join("saved.graph"), &graph_path).unwrap();
                    }
                    "base-order" => {
                        fs::write(&chain, [ids[1], b"\n", ids[0], b"\n"].concat()).unwrap()
                    }
                    "simultaneous" => {
                        fs::write(common.join("objects/info/commit-graph"), &graph_bytes).unwrap()
                    }
                    _ => unreachable!(),
                }
                assert!(check().is_err(), "{format:?}/{case}");
                match case {
                    "duplicate" | "traversal" | "base-order" => fs::write(&chain, &bytes).unwrap(),
                    "missing" => fs::rename(repo.join("saved.graph"), &graph_path).unwrap(),
                    "symlink" => {
                        fs::remove_file(&graph_path).unwrap();
                        fs::rename(repo.join("saved.graph"), &graph_path).unwrap();
                    }
                    "unknown" => fs::remove_file(dir.join("unknown")).unwrap(),
                    "simultaneous" => {
                        fs::remove_file(common.join("objects/info/commit-graph")).unwrap()
                    }
                    _ => unreachable!(),
                }
            }
            // Bounds and retained identity include both chain and graph files.
            for path in [&chain, &graph_path] {
                let mut b = Budget::new();
                let mut m = filesystem::Manifest::new(&common, &mut b).unwrap();
                let names = m.list(b"objects/info", &mut b).unwrap();
                assert!(capture(&mut m, &names, format, &mut b).unwrap());
                fs::write(repo.join("replacement"), fs::read(path).unwrap()).unwrap();
                fs::rename(repo.join("replacement"), path).unwrap();
                assert!(matches!(m.recheck(&mut b), Err(IncompleteReason::Changed)));
            }
        }
    }
}
