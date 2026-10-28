//! Closed `work.recovery-preparation.v1` intent/result codec. Historical bytes
//! never become a fresh plan. Tests authored with the protocol cases.
#[cfg(test)]
use super::super::hex;
use super::super::{frame, valid_ref, Store};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub(super) const MAGIC: &[u8] = b"work.recovery-preparation.v1";
const KIND_INTENT: &[u8] = b"intent";
const KIND_RESULT: &[u8] = b"result";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PlanEntry {
    pub reference: String,
    pub oid: String,
    pub object_type: String,
    pub provenance: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Intent {
    pub operation: Uuid,
    pub result_id: Uuid,
    pub checkout: Uuid,
    pub authority: Vec<u8>,
    pub common_path: Vec<u8>,
    pub common_dev: u64,
    pub common_ino: u64,
    pub private_path: Vec<u8>,
    pub boot: Vec<u8>,
    pub context_digest: [u8; 32],
    pub policy_digest: [u8; 32],
    pub source_commitment: [u8; 32],
    pub source_witness: Vec<u8>,
    pub object_format: String,
    pub plan: Vec<PlanEntry>,
    pub create_only: bool,
    pub result_length: u64,
    pub result_dev: u64,
    pub result_ino: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct ResultRecord {
    pub operation: Uuid,
    pub intent_checksum: [u8; 32],
    pub result_id: Uuid,
    pub checkout: Uuid,
    pub target_count: u64,
    pub targets: Vec<(String, String)>,
    pub closure_digest: [u8; 32],
    pub sync_ack: bool,
    pub retirement_authority: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Record {
    Intent(Box<Intent>),
    Result(ResultRecord),
}

pub(super) fn valid_generated_ref(
    checkout: Uuid,
    format: &str,
    reference: &str,
    oid: &str,
) -> Result<(), &'static str> {
    let width = match format {
        "sha1" => 40,
        "sha256" => 64,
        _ => return Err("record_corrupt"),
    };
    if oid.len() != width
        || !oid.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
        || oid.bytes().all(|c| c == b'0')
    {
        return Err("record_corrupt");
    }
    let expected = format!("refs/work-recovery/{checkout}/{format}/{oid}");
    if reference != expected || !valid_ref(reference.as_bytes()) {
        return Err("record_corrupt");
    }
    Ok(())
}

pub(super) fn valid_plan_entry(
    checkout: Uuid,
    format: &str,
    entry: &PlanEntry,
) -> Result<(), &'static str> {
    if entry.provenance.len() > 65_536 {
        return Err("record_corrupt");
    }
    if !matches!(
        entry.object_type.as_str(),
        "commit" | "tree" | "blob" | "tag"
    ) {
        return Err("record_corrupt");
    }
    valid_generated_ref(checkout, format, &entry.reference, &entry.oid)?;
    super::super::preservation::validate_provenance(&entry.provenance)?;
    Ok(())
}

pub(super) fn encode_intent(intent: &Intent) -> Result<Vec<u8>, &'static str> {
    if !intent.create_only {
        return Err("create_only_required");
    }
    if intent.operation == intent.result_id {
        return Err("record_corrupt");
    }
    let mut bytes = Vec::new();
    frame(&mut bytes, 0, MAGIC);
    frame(&mut bytes, 1, KIND_INTENT);
    frame(&mut bytes, 2, &1u32.to_be_bytes());
    frame(&mut bytes, 3, intent.operation.to_string().as_bytes());
    frame(&mut bytes, 4, intent.result_id.to_string().as_bytes());
    frame(&mut bytes, 5, intent.checkout.to_string().as_bytes());
    frame(&mut bytes, 6, &intent.authority);
    frame(&mut bytes, 7, &intent.common_path);
    frame(&mut bytes, 8, &intent.common_dev.to_be_bytes());
    frame(&mut bytes, 9, &intent.common_ino.to_be_bytes());
    frame(&mut bytes, 10, &intent.private_path);
    frame(&mut bytes, 11, &intent.boot);
    frame(&mut bytes, 12, &intent.context_digest);
    frame(&mut bytes, 13, &intent.policy_digest);
    frame(&mut bytes, 14, &intent.source_commitment);
    frame(&mut bytes, 15, intent.object_format.as_bytes());
    frame(&mut bytes, 16, &(intent.plan.len() as u64).to_be_bytes());
    let mut previous = None;
    for entry in &intent.plan {
        if previous.as_ref().is_some_and(|p| p >= &entry.reference) {
            return Err("plan_order");
        }
        valid_plan_entry(intent.checkout, &intent.object_format, entry)?;
        previous = Some(entry.reference.clone());
        frame(&mut bytes, 17, entry.reference.as_bytes());
        frame(&mut bytes, 18, entry.oid.as_bytes());
        frame(&mut bytes, 19, entry.object_type.as_bytes());
        frame(&mut bytes, 20, &entry.provenance);
    }
    frame(&mut bytes, 21, &[1]);
    frame(&mut bytes, 22, &intent.source_witness);
    frame(&mut bytes, 23, &intent.result_length.to_be_bytes());
    frame(&mut bytes, 24, &intent.result_dev.to_be_bytes());
    frame(&mut bytes, 25, &intent.result_ino.to_be_bytes());
    let checksum = Sha256::digest(&bytes);
    frame(&mut bytes, 26, &checksum);
    if bytes.len() as u64 > 2 * 1024 * 1024 {
        return Err("encoding_limit");
    }
    Ok(bytes)
}

pub(super) fn encode_result(result: &ResultRecord) -> Result<Vec<u8>, &'static str> {
    if result.retirement_authority || !result.sync_ack {
        return Err("result_authority");
    }
    if result.targets.len() as u64 != result.target_count {
        return Err("result_count");
    }
    let mut bytes = Vec::new();
    frame(&mut bytes, 0, MAGIC);
    frame(&mut bytes, 1, KIND_RESULT);
    frame(&mut bytes, 2, &1u32.to_be_bytes());
    frame(&mut bytes, 3, result.operation.to_string().as_bytes());
    frame(&mut bytes, 4, &result.intent_checksum);
    frame(&mut bytes, 5, result.result_id.to_string().as_bytes());
    frame(&mut bytes, 6, result.checkout.to_string().as_bytes());
    frame(&mut bytes, 7, &result.target_count.to_be_bytes());
    let mut previous = None;
    for (reference, oid) in &result.targets {
        if previous.as_ref().is_some_and(|p| p >= reference) {
            return Err("result_order");
        }
        previous = Some(reference.clone());
        let format = match oid.len() {
            40 => "sha1",
            64 => "sha256",
            _ => return Err("record_corrupt"),
        };
        valid_generated_ref(result.checkout, format, reference, oid)?;
        frame(&mut bytes, 8, reference.as_bytes());
        frame(&mut bytes, 9, oid.as_bytes());
    }
    frame(&mut bytes, 10, &result.closure_digest);
    frame(&mut bytes, 11, &[1]);
    frame(&mut bytes, 12, &[0]);
    let checksum = Sha256::digest(&bytes);
    frame(&mut bytes, 13, &checksum);
    if bytes.len() as u64 > 2 * 1024 * 1024 {
        return Err("encoding_limit");
    }
    Ok(bytes)
}

pub(super) fn intent_checksum(bytes: &[u8]) -> Result<[u8; 32], &'static str> {
    match decode(bytes)? {
        Record::Intent(_) => {
            let mut c = Cursor::new(bytes);
            while c.peek() != Some(26) {
                c.any().map_err(|_| "record_corrupt")?;
            }
            Ok(Sha256::digest(&bytes[..c.at]).into())
        }
        Record::Result(_) => Err("record_kind"),
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
    canonical: Vec<u8>,
}
impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            at: 0,
            canonical: Vec::new(),
        }
    }
    fn done(&self) -> bool {
        self.at == self.bytes.len()
    }
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }
    fn any(&mut self) -> Result<(u8, &'a [u8]), &'static str> {
        let header = self
            .bytes
            .get(self.at..self.at.saturating_add(9))
            .ok_or("record_corrupt")?;
        let length = u64::from_be_bytes(header[1..].try_into().map_err(|_| "record_corrupt")?);
        let length = usize::try_from(length).map_err(|_| "record_corrupt")?;
        let start = self.at + 9;
        let end = start.checked_add(length).ok_or("record_corrupt")?;
        let value = self.bytes.get(start..end).ok_or("record_corrupt")?;
        let tag = header[0];
        self.at = end;
        frame(&mut self.canonical, tag, value);
        Ok((tag, value))
    }
    fn field(&mut self, expected: u8) -> Result<&'a [u8], &'static str> {
        let (tag, value) = self.any()?;
        if tag != expected {
            return Err("record_corrupt");
        }
        Ok(value)
    }
    fn uuid(&mut self, tag: u8) -> Result<Uuid, &'static str> {
        let text = std::str::from_utf8(self.field(tag)?).map_err(|_| "record_corrupt")?;
        let id = Uuid::parse_str(text).map_err(|_| "record_corrupt")?;
        if id.get_version_num() != 7
            || id.get_variant() != uuid::Variant::RFC4122
            || id.to_string() != text
        {
            return Err("record_corrupt");
        }
        Ok(id)
    }
    fn hash(&mut self, tag: u8) -> Result<[u8; 32], &'static str> {
        self.field(tag)?.try_into().map_err(|_| "record_corrupt")
    }
    fn u64(&mut self, tag: u8) -> Result<u64, &'static str> {
        Ok(u64::from_be_bytes(
            self.field(tag)?.try_into().map_err(|_| "record_corrupt")?,
        ))
    }
    fn u32(&mut self, tag: u8) -> Result<u32, &'static str> {
        Ok(u32::from_be_bytes(
            self.field(tag)?.try_into().map_err(|_| "record_corrupt")?,
        ))
    }
    fn end(self) -> Result<(), &'static str> {
        if !self.done() || self.canonical != self.bytes {
            return Err("record_corrupt");
        }
        Ok(())
    }
}

pub(super) fn decode(bytes: &[u8]) -> Result<Record, &'static str> {
    if bytes.len() as u64 > 2 * 1024 * 1024 || bytes.is_empty() {
        return Err("record_corrupt");
    }
    let mut c = Cursor::new(bytes);
    if c.field(0)? != MAGIC {
        return Err("record_corrupt");
    }
    match c.field(1)? {
        KIND_INTENT => decode_intent(bytes, c),
        KIND_RESULT => decode_result(bytes, c),
        _ => Err("record_corrupt"),
    }
}

fn decode_intent<'a>(bytes: &'a [u8], mut c: Cursor<'a>) -> Result<Record, &'static str> {
    if c.u32(2)? != 1 {
        return Err("record_corrupt");
    }
    let operation = c.uuid(3)?;
    let result_id = c.uuid(4)?;
    let checkout = c.uuid(5)?;
    if operation == result_id {
        return Err("record_corrupt");
    }
    let authority = c.field(6)?.to_vec();
    let common_path = c.field(7)?.to_vec();
    let common_dev = c.u64(8)?;
    let common_ino = c.u64(9)?;
    let private_path = c.field(10)?.to_vec();
    let boot = c.field(11)?.to_vec();
    let context_digest = c.hash(12)?;
    let policy_digest = c.hash(13)?;
    let source_commitment = c.hash(14)?;
    let object_format = std::str::from_utf8(c.field(15)?)
        .map_err(|_| "record_corrupt")?
        .to_owned();
    if object_format != "sha1" && object_format != "sha256" {
        return Err("record_corrupt");
    }
    let count = c.u64(16)?;
    if count > 4096 {
        return Err("record_corrupt");
    }
    let mut plan = Vec::new();
    let mut previous = None;
    for _ in 0..count {
        let reference = std::str::from_utf8(c.field(17)?)
            .map_err(|_| "record_corrupt")?
            .to_owned();
        let oid = std::str::from_utf8(c.field(18)?)
            .map_err(|_| "record_corrupt")?
            .to_owned();
        let object_type = std::str::from_utf8(c.field(19)?)
            .map_err(|_| "record_corrupt")?
            .to_owned();
        let provenance = c.field(20)?.to_vec();
        if previous.as_ref().is_some_and(|p| p >= &reference) {
            return Err("record_corrupt");
        }
        previous = Some(reference.clone());
        let entry = PlanEntry {
            reference,
            oid,
            object_type,
            provenance,
        };
        valid_plan_entry(checkout, &object_format, &entry)?;
        plan.push(entry);
    }
    if c.field(21)? != [1] {
        return Err("record_corrupt");
    }
    let source_witness = c.field(22)?.to_vec();
    let result_length = c.u64(23)?;
    let result_dev = c.u64(24)?;
    let result_ino = c.u64(25)?;
    if result_length == 0 || result_length > 2 * 1024 * 1024 {
        return Err("record_corrupt");
    }
    let checksum_at = c.at;
    if c.hash(26)? != hash32(&Sha256::digest(&bytes[..checksum_at])) {
        return Err("record_corrupt");
    }
    c.end()?;
    Ok(Record::Intent(Box::new(Intent {
        operation,
        result_id,
        checkout,
        authority,
        common_path,
        common_dev,
        common_ino,
        private_path,
        boot,
        context_digest,
        policy_digest,
        source_commitment,
        source_witness,
        object_format,
        plan,
        create_only: true,
        result_length,
        result_dev,
        result_ino,
    })))
}

fn decode_result<'a>(bytes: &'a [u8], mut c: Cursor<'a>) -> Result<Record, &'static str> {
    if c.u32(2)? != 1 {
        return Err("record_corrupt");
    }
    let operation = c.uuid(3)?;
    let intent_checksum = c.hash(4)?;
    let result_id = c.uuid(5)?;
    let checkout = c.uuid(6)?;
    if operation == result_id {
        return Err("record_corrupt");
    }
    let target_count = c.u64(7)?;
    if target_count > 4096 {
        return Err("record_corrupt");
    }
    let mut targets = Vec::new();
    let mut previous = None;
    for _ in 0..target_count {
        let reference = std::str::from_utf8(c.field(8)?)
            .map_err(|_| "record_corrupt")?
            .to_owned();
        let oid = std::str::from_utf8(c.field(9)?)
            .map_err(|_| "record_corrupt")?
            .to_owned();
        if previous.as_ref().is_some_and(|p| p >= &reference) {
            return Err("record_corrupt");
        }
        previous = Some(reference.clone());
        let format = match oid.len() {
            40 => "sha1",
            64 => "sha256",
            _ => return Err("record_corrupt"),
        };
        valid_generated_ref(checkout, format, &reference, &oid)?;
        targets.push((reference, oid));
    }
    let closure_digest = c.hash(10)?;
    if c.field(11)? != [1] {
        return Err("record_corrupt");
    }
    if c.field(12)? != [0] {
        return Err("record_corrupt");
    }
    let checksum_at = c.at;
    if c.hash(13)? != hash32(&Sha256::digest(&bytes[..checksum_at])) {
        return Err("record_corrupt");
    }
    c.end()?;
    Ok(Record::Result(ResultRecord {
        operation,
        intent_checksum,
        result_id,
        checkout,
        target_count,
        targets,
        closure_digest,
        sync_ack: true,
        retirement_authority: false,
    }))
}

fn hash32(digest: &sha2::digest::Output<Sha256>) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(digest);
    out
}

pub(super) fn authority_bytes(store: &Store) -> Vec<u8> {
    super::super::receipts::authority_bytes_for_recovery(store)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_provenance() -> Vec<u8> {
        let mut out = Vec::new();
        frame(&mut out, 1, b"named_ref");
        frame(&mut out, 2, b"");
        frame(&mut out, 3, &[]);
        out
    }

    fn sample_intent() -> Intent {
        let operation = Uuid::now_v7();
        let result_id = Uuid::now_v7();
        let checkout = Uuid::now_v7();
        let oid = "a".repeat(40);
        Intent {
            operation,
            result_id,
            checkout,
            authority: b"authority".to_vec(),
            common_path: b"/abs/common.git".to_vec(),
            common_dev: 1,
            common_ino: 2,
            private_path: b"/abs/private".to_vec(),
            boot: b"boot".to_vec(),
            context_digest: [3; 32],
            policy_digest: [4; 32],
            source_commitment: [5; 32],
            source_witness: b"work.recovery.source.v1".to_vec(),
            object_format: "sha1".into(),
            plan: vec![PlanEntry {
                reference: format!("refs/work-recovery/{checkout}/sha1/{oid}"),
                oid,
                object_type: "commit".into(),
                provenance: sample_provenance(),
            }],
            create_only: true,
            result_length: 128,
            result_dev: 8,
            result_ino: 9,
        }
    }

    #[test]
    fn intent_round_trip_and_rejects_unknown_fields_duplicates_and_order() {
        let intent = sample_intent();
        let bytes = encode_intent(&intent).unwrap();
        match decode(&bytes).unwrap() {
            Record::Intent(decoded) => assert_eq!(*decoded, intent),
            Record::Result(_) => panic!("kind"),
        }
        let mut extra = bytes.clone();
        extra.extend_from_slice(&bytes);
        assert_eq!(decode(&extra), Err("record_corrupt"));
        let mut swapped = encode_intent(&intent).unwrap();
        swapped[0] = 9;
        assert_eq!(decode(&swapped), Err("record_corrupt"));
        let mut unordered = intent;
        let oid_b = "9".repeat(40);
        unordered.plan.push(PlanEntry {
            reference: format!("refs/work-recovery/{}/sha1/{oid_b}", unordered.checkout),
            oid: oid_b,
            object_type: "blob".into(),
            provenance: vec![],
        });
        assert!(encode_intent(&unordered).is_err());
    }

    #[test]
    fn generated_ref_rejects_noncanonical_names_and_zero_oids() {
        let mut intent = sample_intent();
        intent.plan[0].reference = "refs/work-recovery/x/sha1/aa".into();
        intent.plan[0].oid = "aa".into();
        assert_eq!(encode_intent(&intent), Err("record_corrupt"));
        let mut intent = sample_intent();
        intent.plan[0].oid = "0".repeat(40);
        intent.plan[0].reference = format!(
            "refs/work-recovery/{}/sha1/{}",
            intent.checkout, intent.plan[0].oid
        );
        assert_eq!(encode_intent(&intent), Err("record_corrupt"));
        let mut intent = sample_intent();
        intent.plan[0].oid = intent.plan[0].oid.to_uppercase();
        intent.plan[0].reference = format!(
            "refs/work-recovery/{}/sha1/{}",
            intent.checkout, intent.plan[0].oid
        );
        assert_eq!(encode_intent(&intent), Err("record_corrupt"));
        let mut intent = sample_intent();
        assert!(intent.operation != intent.result_id);
        intent.result_id = intent.operation;
        assert_eq!(encode_intent(&intent), Err("record_corrupt"));
    }

    #[test]
    fn result_binds_intent_checksum_and_false_authority() {
        let intent = sample_intent();
        let encoded = encode_intent(&intent).unwrap();
        let checksum = intent_checksum(&encoded).unwrap();
        let result = ResultRecord {
            operation: intent.operation,
            intent_checksum: checksum,
            result_id: intent.result_id,
            checkout: intent.checkout,
            target_count: 1,
            targets: vec![(intent.plan[0].reference.clone(), intent.plan[0].oid.clone())],
            closure_digest: [9; 32],
            sync_ack: true,
            retirement_authority: false,
        };
        let bytes = encode_result(&result).unwrap();
        match decode(&bytes).unwrap() {
            Record::Result(decoded) => assert_eq!(decoded, result),
            Record::Intent(_) => panic!("kind"),
        }
        let mut forged = result;
        forged.retirement_authority = true;
        assert!(encode_result(&forged).is_err());
        let mut mismatched = ResultRecord {
            operation: intent.operation,
            intent_checksum: checksum,
            result_id: intent.result_id,
            checkout: Uuid::now_v7(),
            target_count: 1,
            targets: vec![(intent.plan[0].reference.clone(), intent.plan[0].oid.clone())],
            closure_digest: [9; 32],
            sync_ack: true,
            retirement_authority: false,
        };
        mismatched.targets = vec![(
            format!(
                "refs/work-recovery/{}/sha1/{}",
                mismatched.checkout, intent.plan[0].oid
            ),
            intent.plan[0].oid.clone(),
        )];
        let mismatched_bytes = encode_result(&mismatched).unwrap();
        match decode(&mismatched_bytes).unwrap() {
            Record::Result(decoded) => {
                assert_ne!(decoded.checkout, intent.checkout);
                assert_eq!(decoded.intent_checksum, checksum);
            }
            Record::Intent(_) => panic!("kind"),
        }
        mismatched.checkout = intent.checkout;
        mismatched.targets = vec![(intent.plan[0].reference.clone(), "b".repeat(40))];
        assert_eq!(encode_result(&mismatched), Err("record_corrupt"));
    }

    #[test]
    fn result_decode_rejects_malformed_generated_refs() {
        let intent = sample_intent();
        let checksum = [7; 32];
        let mut result = ResultRecord {
            operation: intent.operation,
            intent_checksum: checksum,
            result_id: intent.result_id,
            checkout: intent.checkout,
            target_count: 1,
            targets: vec![("refs/work-recovery/x/sha1/aa".into(), "aa".into())],
            closure_digest: [9; 32],
            sync_ack: true,
            retirement_authority: false,
        };
        assert_eq!(encode_result(&result), Err("record_corrupt"));
        result.targets = vec![(intent.plan[0].reference.clone(), intent.plan[0].oid.clone())];
        let bytes = encode_result(&result).unwrap();
        match decode(&bytes).unwrap() {
            Record::Result(decoded) => assert_eq!(decoded.targets, result.targets),
            Record::Intent(_) => panic!("kind"),
        }
    }

    #[test]
    fn rechecksummed_intent_with_contradictory_source_commitment_still_decodes() {
        let mut intent = sample_intent();
        intent.source_commitment = hash32(&Sha256::digest(&intent.source_witness));
        let matching = encode_intent(&intent).unwrap();
        match decode(&matching).unwrap() {
            Record::Intent(decoded) => {
                assert_eq!(decoded.source_commitment, intent.source_commitment)
            }
            Record::Result(_) => panic!("kind"),
        }
        intent.source_commitment = [9; 32];
        let contradictory = encode_intent(&intent).unwrap();
        match decode(&contradictory).unwrap() {
            Record::Intent(decoded) => {
                assert_ne!(
                    decoded.source_commitment,
                    hash32(&Sha256::digest(&decoded.source_witness))
                );
            }
            Record::Result(_) => panic!("kind"),
        }
    }

    #[test]
    fn v1_inspection_magic_is_not_a_recovery_record() {
        let mut bytes = Vec::new();
        frame(&mut bytes, 0, b"work.inspection.receipt.v1");
        frame(&mut bytes, 1, KIND_INTENT);
        assert_eq!(decode(&bytes), Err("record_corrupt"));
        assert_eq!(decode(b""), Err("record_corrupt"));
        assert_eq!(decode(b"{}"), Err("record_corrupt"));
    }

    #[test]
    fn hex_helper_is_stable_for_commitments() {
        assert_eq!(hex(&[0x0a, 0xfb]), "0afb");
    }
}
