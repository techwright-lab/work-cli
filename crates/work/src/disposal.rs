//! Strict policy input, not deletion authority. No default content exemptions.
//! Validation binds a proposed allowlist; it does not inspect or classify files.
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const MAX_POLICY_BYTES: usize = 1024 * 1024;
const MAX_RULES: usize = 64;
const MAX_ENTRIES: usize = 4096;
const MAX_PATH: usize = 4096;
const MAX_DEPTH: usize = 64;
const MAX_FILE: u64 = 16 * 1024 * 1024;
const MAX_TOTAL: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid or unsupported inspection policy: {0}")]
pub struct PolicyError(&'static str);

/// Canonical relative Unix bytes. Display text is never used as identity.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RawPath(Vec<u8>);
impl RawPath {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PolicyError> {
        if bytes.is_empty() || bytes.len() > MAX_PATH || bytes.contains(&0) {
            return Err(PolicyError("path bounds"));
        }
        let mut depth = 0;
        for part in bytes.split(|b| *b == b'/') {
            depth += 1;
            if part.is_empty() || part == b"." || part == b".." || depth > MAX_DEPTH {
                return Err(PolicyError("path components"));
            }
        }
        Ok(Self(bytes.to_vec()))
    }
    pub fn from_hex(wire: &str) -> Result<Self, PolicyError> {
        Self::from_bytes(&decode_hex(wire, MAX_PATH)?)
    }
    pub fn as_bytes(&self) -> &[u8] { &self.0 }
    pub fn to_hex(&self) -> String { encode_hex(&self.0) }
    fn parent(&self) -> Option<Self> {
        self.0.iter().rposition(|b| *b == b'/').map(|n| Self(self.0[..n].to_vec()))
    }
    fn contains(&self, other: &Self) -> bool {
        self == other || (other.0.starts_with(&self.0) && other.0.get(self.0.len()) == Some(&b'/'))
    }
}
impl std::fmt::Debug for RawPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.debug_tuple("RawPathHex").field(&self.to_hex()).finish() }
}
impl Serialize for RawPath {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> { s.serialize_str(&self.to_hex()) }
}
impl<'de> Deserialize<'de> for RawPath {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let wire = String::deserialize(d)?;
        Self::from_hex(&wire).map_err(serde::de::Error::custom)
    }
}
fn decode_hex(wire: &str, maximum: usize) -> Result<Vec<u8>, PolicyError> {
    if wire.is_empty() || wire.len() > maximum * 2 || wire.len() % 2 != 0 {
        return Err(PolicyError("hex bounds"));
    }
    fn digit(b: u8) -> Result<u8, PolicyError> {
        match b { b'0'..=b'9' => Ok(b - b'0'), b'a'..=b'f' => Ok(b - b'a' + 10), _ => Err(PolicyError("noncanonical hex")) }
    }
    wire.as_bytes().chunks_exact(2).map(|p| Ok((digit(p[0])? << 4) | digit(p[1])?)).collect()
}
fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8;16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes { out.push(HEX[(b >> 4) as usize] as char); out.push(HEX[(b & 15) as usize] as char); }
    out
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocument { pub format: u64, pub policies: Vec<Policy> }
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub id: String,
    pub version: String,
    /// Checkout-relative, strict lowercase hex; never a glob.
    pub scope: String,
    pub max_files: u64,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub files: Vec<PolicyFile>,
    pub directories: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFile { pub path: String, pub sha256: String, pub length: u64, pub mode: u32 }

/// A validated proposal only. No Deserialize, filesystem evidence or authority.
#[derive(Debug)]
pub struct ValidatedPolicies { rules: Vec<Rule>, canonical: Vec<u8>, digest: [u8;32] }
impl ValidatedPolicies {
    pub fn digest(&self) -> [u8;32] { self.digest }
    pub fn canonical_bytes(&self) -> &[u8] { &self.canonical }
    pub fn policy_count(&self) -> usize { self.rules.len() }
}
#[derive(Debug)]
struct Rule {
    id: String, version: String, scope: RawPath,
    max_files: u64, max_file_bytes: u64, max_total_bytes: u64,
    files: Vec<ExactFile>, directories: Vec<RawPath>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct ExactFile { path: RawPath, sha256: [u8;32], length: u64, mode: u32 }

/// Bounded convenience parser; configuration integration remains deferred.
pub fn parse_document(bytes: &[u8]) -> Result<ValidatedPolicies, PolicyError> {
    if bytes.len() > MAX_POLICY_BYTES { return Err(PolicyError("document size")); }
    let document = serde_json::from_slice(bytes).map_err(|_| PolicyError("document syntax"))?;
    validate(document)
}
pub fn validate(document: PolicyDocument) -> Result<ValidatedPolicies, PolicyError> {
    if document.format != 1 || document.policies.len() > MAX_RULES { return Err(PolicyError("format or rule limit")); }
    let mut ids = BTreeSet::new();
    let mut rules: Vec<Rule> = Vec::new();
    let mut entries = 0usize;
    for policy in document.policies {
        for label in [&policy.id, &policy.version] {
            if label.is_empty() || label.len() > 128 || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) {
                return Err(PolicyError("id or version"));
            }
        }
        if !ids.insert(policy.id.clone()) { return Err(PolicyError("duplicate policy id")); }
        if policy.max_files > MAX_ENTRIES as u64 || policy.max_file_bytes > MAX_FILE
            || policy.max_total_bytes > MAX_TOTAL || policy.max_file_bytes > policy.max_total_bytes {
            return Err(PolicyError("policy maxima"));
        }
        entries = entries.checked_add(policy.files.len()).and_then(|n| n.checked_add(policy.directories.len())).ok_or(PolicyError("entry limit"))?;
        if entries > MAX_ENTRIES || policy.files.len() as u64 > policy.max_files { return Err(PolicyError("entry limit")); }
        let scope = RawPath::from_hex(&policy.scope)?;
        if rules.iter().any(|p| p.scope.contains(&scope) || scope.contains(&p.scope)) { return Err(PolicyError("overlapping scopes")); }
        let mut directories = BTreeSet::new();
        for wire in policy.directories {
            let path = RawPath::from_hex(&wire)?;
            if !scope.contains(&path) || !directories.insert(path) { return Err(PolicyError("directory coverage")); }
        }
        if !directories.contains(&scope) { return Err(PolicyError("missing scope directory")); }
        for path in &directories {
            if path != &scope && !path.parent().is_some_and(|p| directories.contains(&p)) { return Err(PolicyError("missing parent directory")); }
        }
        let mut files = Vec::new(); let mut paths = BTreeSet::new(); let mut total = 0u64;
        for file in policy.files {
            let path = RawPath::from_hex(&file.path)?;
            if !scope.contains(&path) || directories.contains(&path) || !paths.insert(path.clone())
                || !path.parent().is_some_and(|p| directories.contains(&p)) { return Err(PolicyError("file coverage")); }
            if file.mode & !0o777 != 0 || file.length > policy.max_file_bytes { return Err(PolicyError("file mode or size")); }
            total = total.checked_add(file.length).ok_or(PolicyError("total size"))?;
            if total > policy.max_total_bytes { return Err(PolicyError("total size")); }
            let hash = decode_hex(&file.sha256, 32)?;
            let sha256 = hash.try_into().map_err(|_| PolicyError("SHA256 length"))?;
            files.push(ExactFile { path, sha256, length:file.length, mode:file.mode });
        }
        files.sort_by(|a,b| a.path.cmp(&b.path));
        rules.push(Rule { id:policy.id, version:policy.version, scope, max_files:policy.max_files,
            max_file_bytes:policy.max_file_bytes, max_total_bytes:policy.max_total_bytes,
            files, directories:directories.into_iter().collect() });
    }
    rules.sort_by(|a,b| a.scope.cmp(&b.scope));
    let mut e = Encoder(Vec::new());
    e.field(0, b"work.disposal.policy.v1")?;
    e.number(1, 1)?; // policy format
    e.number(2, 1)?; // classifier contract version, not classification evidence
    e.number(3, rules.len() as u64)?;
    for p in &rules {
        e.field(4, p.scope.as_bytes())?; e.field(5, p.id.as_bytes())?; e.field(6, p.version.as_bytes())?;
        e.number(7, p.max_files)?; e.number(8, p.max_file_bytes)?; e.number(9, p.max_total_bytes)?;
        e.number(10, p.directories.len() as u64)?;
        for path in &p.directories { e.field(11, path.as_bytes())?; }
        e.number(12, p.files.len() as u64)?;
        for file in &p.files {
            e.field(13, file.path.as_bytes())?; e.field(14, &file.sha256)?;
            e.number(15, file.length)?; e.number(16, u64::from(file.mode))?;
        }
    }
    let digest = Sha256::digest(&e.0).into();
    Ok(ValidatedPolicies { rules, canonical:e.0, digest })
}
struct Encoder(Vec<u8>);
impl Encoder {
    fn field(&mut self, tag: u8, bytes: &[u8]) -> Result<(), PolicyError> {
        let size = self.0.len().checked_add(9).and_then(|n| n.checked_add(bytes.len())).ok_or(PolicyError("canonical size"))?;
        if size > MAX_POLICY_BYTES { return Err(PolicyError("canonical size")); }
        self.0.push(tag); self.0.extend_from_slice(&(bytes.len() as u64).to_be_bytes()); self.0.extend_from_slice(bytes); Ok(())
    }
    fn number(&mut self, tag: u8, value: u64) -> Result<(), PolicyError> { self.field(tag, &value.to_be_bytes()) }
}

// Pure comparison for test-only synthetic observations. A3 must supply real
// private membership/coverage proof before enabling production classification.
#[cfg(test)]
fn exact_allowlist(rule: &Rule, files: &[ExactFile], directories: &[RawPath]) -> bool {
    let mut files = files.to_vec(); let mut directories = directories.to_vec();
    files.sort_by(|a,b| a.path.cmp(&b.path)); directories.sort();
    files == rule.files && directories == rule.directories
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthetic membership exists ONLY here. It is not fresh Git proof and is
    // never available to integration callers or production classification.
    #[derive(Clone, Copy)]
    enum Membership { Ignored, Nonignored, Tracked }
    #[derive(Clone)]
    struct SyntheticFile { entry: ExactFile, membership: Membership, links: u64 }

    fn policy() -> ValidatedPolicies {
        validate(PolicyDocument { format: 1, policies: vec![Policy {
            id: "explicit".into(), version: "v1".into(), scope: "6361636865".into(),
            max_files: 1, max_file_bytes: 3, max_total_bytes: 3,
            directories: vec!["6361636865".into(), "63616368652f656d707479".into()],
            files: vec![PolicyFile { path: "63616368652f61".into(),
                sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
                length: 3, mode: 0o600 }],
        }] }).unwrap()
    }
    fn synthetic_match(p: &ValidatedPolicies, files: &[SyntheticFile], dirs: &[RawPath], complete: bool) -> bool {
        complete && files.iter().all(|f| matches!(f.membership, Membership::Ignored) && f.links == 1)
            && exact_allowlist(&p.rules[0], &files.iter().map(|f| f.entry.clone()).collect::<Vec<_>>(), dirs)
    }
    fn inputs(p: &ValidatedPolicies) -> (Vec<SyntheticFile>, Vec<RawPath>) {
        (p.rules[0].files.iter().cloned().map(|entry| SyntheticFile {
            entry, membership: Membership::Ignored, links: 1,
        }).collect(), p.rules[0].directories.clone())
    }
    #[test]
    fn policy_requires_exact_content_and_directory_coverage() {
        let p = policy(); let (files, dirs) = inputs(&p);
        assert!(synthetic_match(&p, &files, &dirs, true));
        assert!(!synthetic_match(&p, &files, &dirs, false));
        for mutation in ["hash", "length", "mode", "missing", "secret", "emptydir", "hardlink", "marker", "pyc"] {
            let mut files = files.clone(); let mut dirs = dirs.clone();
            match mutation {
                "hash" => files[0].entry.sha256 = [0;32],
                "length" => files[0].entry.length += 1,
                "mode" => files[0].entry.mode = 0o644,
                "missing" => { dirs.pop(); },
                "secret" | "marker" | "pyc" => {
                    let mut extra = files[0].clone();
                    extra.entry.path = RawPath::from_bytes(format!("cache/{mutation}").as_bytes()).unwrap();
                    files.push(extra);
                }
                "emptydir" => dirs.push(RawPath::from_bytes(b"cache/extra").unwrap()),
                "hardlink" => files[0].links = 2,
                _ => unreachable!(),
            }
            assert!(!synthetic_match(&p, &files, &dirs, true), "{mutation}");
        }
    }
    #[test]
    fn nonignored_and_tracked_are_never_disposable() {
        let p = policy(); let (mut files, dirs) = inputs(&p);
        for membership in [Membership::Nonignored, Membership::Tracked] {
            files[0].membership = membership;
            assert!(!synthetic_match(&p, &files, &dirs, true));
        }
    }
}
