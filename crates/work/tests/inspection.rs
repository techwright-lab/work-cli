//! Public inspection remains refusing until A3 and context integration.
#[path = "support/inspection_fixture.rs"]
mod fixture;
use work_cli::{disposal::{validate, PolicyDocument}, inspection::{self, Coverage, IncompleteReason}, store::Store};

#[test]
fn raw_names_and_ignored_descendants_are_all_observed() {
    // Filesystem census positives live in inspection::tests with private access.
    // This linked fixture supplies names, NOT proof of ignored membership.
    let f = fixture::InspectionFixture::linked();
    let names = f.raw_payloads();
    for name in names { assert!(f.path(&name).exists()); }
    let mut store = Store::open(&f.temp.path().join("authority"), std::slice::from_ref(&f.checkout)).unwrap();
    let policies = validate(PolicyDocument { format: 1, policies: vec![] }).unwrap();
    let observation = inspection::inspect(&mut store, uuid::Uuid::now_v7(), &policies).unwrap();
    assert_eq!(observation.coverage(), Coverage::Incomplete);
    assert!(observation.reasons().contains(&IncompleteReason::GitProofUnavailable));
    assert!(observation.reasons().contains(&IncompleteReason::RegistrationEnvelopeOpen));
    assert_eq!(observation.counters().observed_file_bytes, 0);
    // The public seam deliberately performs no path or database lookup yet.
    assert_eq!(observation.counters().child_launches, 0);
}

#[test]
fn validation_cannot_restore_fresh_inspection_evidence() {
    let f = fixture::InspectionFixture::directory();
    let mut store = Store::open(&f.temp.path().join("authority"), std::slice::from_ref(&f.checkout)).unwrap();
    let policies = validate(PolicyDocument { format:1, policies:vec![] }).unwrap();
    assert_eq!(inspection::inspect(&mut store, uuid::Uuid::now_v7(), &policies).unwrap().coverage(), Coverage::Incomplete);
}
