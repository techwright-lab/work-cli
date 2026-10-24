//! SOURCE FIRST; isolated CI only. No local RED/GREEN claim.
#[path = "support/inspection_fixture.rs"]
mod fixture;
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
};
use work_cli as work_cli_api;
use work_cli::{
    disposal::{validate, Policy, PolicyDocument},
    inspection::{self, Coverage, ReceiptError},
    store::Store,
};

fn empty() -> work_cli::disposal::ValidatedPolicies {
    validate(PolicyDocument {
        format: 1,
        policies: vec![],
    })
    .unwrap()
}
fn reopen(f: &fixture::ManagedFixture) -> Store {
    Store::open_existing_registered_mut(
        &f.temp.path().join("registry"),
        &f.temp.path().join("authority"),
        std::slice::from_ref(&f.root),
    )
    .unwrap()
}
#[test]
fn record_reopen_passive_read_preserves_policy_digest_and_lifecycle() {
    let mut f = fixture::ManagedFixture::new("sha1", "2");
    fs::create_dir(f.path(b"cache")).unwrap();
    let policies = validate(PolicyDocument {
        format: 1,
        policies: vec![Policy {
            id: "empty-cache".into(),
            version: "release-7".into(),
            scope: "6361636865".into(),
            max_files: 0,
            max_file_bytes: 0,
            max_total_bytes: 0,
            files: vec![],
            directories: vec!["6361636865".into()],
        }],
    })
    .unwrap();
    let events = f.store.pending_events(100).unwrap();
    let db = fs::read(f.temp.path().join("authority/store.sqlite")).unwrap();
    let wal = fs::read(f.temp.path().join("authority/store.sqlite-wal")).unwrap();
    let result =
        inspection::inspect_and_record(&mut f.store, f.allocation.checkout, &policies).unwrap();
    assert_eq!(
        result.observation.coverage(),
        Coverage::Complete,
        "{:?}",
        result.observation.reasons()
    );
    assert!(result.observation.findings().is_empty());
    let receipt = result.receipt.unwrap();
    assert_eq!(receipt.digest(), result.observation.digest());
    let store = reopen(&f);
    let read = inspection::read_receipt(&store, receipt.id()).unwrap();
    assert_eq!(read.checkout(), f.allocation.checkout);
    assert_eq!(read.id(), receipt.id());
    assert_eq!(read.digest(), receipt.digest());
    assert_eq!(read.coverage(), Coverage::Complete);
    assert_eq!(
        read.canonical_observation(),
        result.observation.canonical_bytes()
    );
    assert_eq!(read.policy_digest(), policies.digest());
    assert_eq!(events, f.store.pending_events(100).unwrap());
    assert_eq!(f.store.charged(&f.repo, None).unwrap(), 1);
    assert_eq!(
        db,
        fs::read(f.temp.path().join("authority/store.sqlite")).unwrap()
    );
    assert_eq!(
        wal,
        fs::read(f.temp.path().join("authority/store.sqlite-wal")).unwrap()
    );
    // Historical bytes do not require today's checkout contents to match.
    fs::write(f.path(b"tracked"), b"later contents").unwrap();
    assert_eq!(
        inspection::read_receipt(&store, receipt.id())
            .unwrap()
            .digest(),
        receipt.digest()
    );
    let directory = f.temp.path().join("authority/inspection-receipts-v1");
    assert_eq!(
        fs::metadata(&directory).unwrap().permissions().mode() & 0o7777,
        0o700
    );
    assert_eq!(
        fs::metadata(directory.join(format!("{}.receipt", receipt.id())))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
}
#[test]
fn incomplete_native_object_failure_can_record_provenance_not_freshness() {
    let mut f = fixture::ManagedFixture::new("sha1", "2");
    // Break only the committed blob in an owned fixture, leaving its bounded
    // native input manifest intact. Native Git, not a positive fake, refuses it.
    use sha2::{Digest, Sha256};
    let marker = Sha256::digest(b"not an object");
    let mut changed = false;
    for prefix in fs::read_dir(f.common().join("objects")).unwrap() {
        let prefix = prefix.unwrap();
        if prefix.file_name().as_encoded_bytes().len() != 2 {
            continue;
        }
        for object in fs::read_dir(prefix.path()).unwrap() {
            let path = object.unwrap().path();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            fs::write(path, marker).unwrap();
            changed = true;
        }
    }
    assert!(changed);
    let result =
        inspection::inspect_and_record(&mut f.store, f.allocation.checkout, &empty()).unwrap();
    assert_eq!(result.observation.coverage(), Coverage::Incomplete);
    let receipt = result.receipt.unwrap();
    assert_eq!(
        inspection::read_receipt(&f.store, receipt.id())
            .unwrap()
            .coverage(),
        Coverage::Incomplete
    );
}
#[test]
fn nondurable_default_missing_context_and_unsafe_directory_do_not_publish() {
    let mut f = fixture::ManagedFixture::new("sha1", "2");
    let directory = f.temp.path().join("authority/inspection-receipts-v1");
    assert_eq!(f.inspect(&empty()).coverage(), Coverage::Complete);
    assert!(!directory.exists());
    let result =
        inspection::inspect_and_record(&mut f.store, uuid::Uuid::now_v7(), &empty()).unwrap();
    assert_eq!(result.observation.coverage(), Coverage::Incomplete);
    assert!(matches!(result.receipt, Err(ReceiptError::Conflict)));
    assert!(!directory.exists());
    symlink(f.temp.path(), &directory).unwrap();
    let result =
        inspection::inspect_and_record(&mut f.store, f.allocation.checkout, &empty()).unwrap();
    assert!(matches!(
        result.receipt,
        Err(ReceiptError::UnsafeReceiptStore)
    ));
}
#[test]
fn preservation_findings_remain_passive_after_recording() {
    let mut f = fixture::ManagedFixture::new("sha1", "2");
    fs::write(f.path(b"untracked"), b"do-not-disclose-payload").unwrap();
    let result =
        inspection::inspect_and_record(&mut f.store, f.allocation.checkout, &empty()).unwrap();
    assert_eq!(result.observation.coverage(), Coverage::Complete);
    let receipt = result.receipt.unwrap();
    let data = inspection::read_receipt(&f.store, receipt.id()).unwrap();
    assert_eq!(data.findings().len(), result.observation.findings().len());
    assert!(data
        .findings()
        .iter()
        .any(|finding| finding.kind() == inspection::FindingKind::Untracked));
    assert!(!data
        .canonical_observation()
        .windows(b"do-not-disclose-payload".len())
        .any(|w| w == b"do-not-disclose-payload"));
}
#[test]
fn corrupt_passive_read_is_not_missing_and_never_repairs() {
    let mut f = fixture::ManagedFixture::new("sha1", "2");
    assert!(matches!(
        inspection::read_receipt(&f.store, uuid::Uuid::now_v7()),
        Err(ReceiptError::Missing)
    ));
    let result =
        inspection::inspect_and_record(&mut f.store, f.allocation.checkout, &empty()).unwrap();
    let id = result.receipt.unwrap().id();
    let path = f
        .temp
        .path()
        .join(format!("authority/inspection-receipts-v1/{id}.receipt"));
    let mut bytes = fs::read(&path).unwrap();
    bytes[20] ^= 1;
    fs::write(&path, &bytes).unwrap();
    assert!(matches!(
        inspection::read_receipt(&f.store, id),
        Err(ReceiptError::Corrupt)
    ));
    assert_eq!(fs::read(path).unwrap(), bytes);
}
