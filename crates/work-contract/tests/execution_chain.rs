use serde_json::{json, Value};
use work_contract::{ChainText, ExecutionChain, ExecutionEntry};

#[test]
fn public_constructors_enforce_the_same_portable_invariants() {
    assert!(ExecutionChain::new(vec![]).is_err());
    let model = ExecutionEntry::Model {
        provider: ChainText::new("p".into()).unwrap(),
        model: ChainText::new("m".into()).unwrap(),
    };
    assert!(ExecutionChain::new(vec![model.clone()]).is_err());
    let executor = ExecutionEntry::Executor {
        system: ChainText::new(" exact ".into()).unwrap(),
        session_ref: None,
    };
    assert!(ExecutionChain::new(vec![executor.clone(); 33]).is_err());
    let chain = ExecutionChain::new(vec![executor, model]).unwrap();
    assert_eq!(chain.entries().len(), 2);
    let value = serde_json::to_value(&chain).unwrap();
    assert_eq!(value[0]["system"], " exact ");
    assert_eq!(
        serde_json::from_value::<ExecutionChain>(value).unwrap(),
        chain
    );
    for bad in ["".into(), "\u{7f}".into(), "x".repeat(4097)] {
        assert!(ChainText::new(bad).is_err());
    }
    // Contract bound is characters, not UTF-8 bytes.
    assert!(ChainText::new("é".repeat(4096)).is_ok());
}

#[test]
fn portable_chains_validate_without_normalizing_or_accepting_configuration() {
    let good = json!([{"kind":"executor","system":" cli ","session_ref":"session"}, {"kind":"model","provider":"provider","model":"model"}]);
    let parsed = serde_json::from_value::<ExecutionChain>(good.clone());
    assert!(
        parsed.is_ok(),
        "structured portable chain must be accepted: {parsed:?}"
    );
    assert_eq!(serde_json::to_value(parsed.unwrap()).unwrap(), good);
    let mut cases = vec![
        json!([{"kind":"executor","system":"cli","session_ref":null}]),
        json!("legacy placeholder"),
        json!([]),
        json!([{"kind":"model","provider":"p","model":"m"}]),
        json!([{"kind":"executor","system":"cli","command":"secret"}]),
    ];
    for text in [
        "".to_owned(),
        " \u{a0}".into(),
        "bad\nvalue".into(),
        "x".repeat(4097),
    ] {
        cases.push(json!([{"kind":"executor","system":text}]));
        cases.push(json!([{"kind":"executor","system":"cli","session_ref":text}]));
        cases.push(json!([{"kind":"executor","system":"cli"},{"kind":"model","provider":"p","model":text}]));
    }
    cases.push(Value::Array(vec![
        json!({"kind":"executor","system":"cli"});
        33
    ]));
    let schema = schemars::schema_for!(ExecutionChain);
    let validator = jsonschema::validator_for(&serde_json::to_value(schema).unwrap()).unwrap();
    assert!(validator.is_valid(&good));
    for bad in cases {
        assert!(
            serde_json::from_value::<ExecutionChain>(bad.clone()).is_err(),
            "runtime accepted {bad}"
        );
        assert!(!validator.is_valid(&bad), "schema accepted {bad}");
    }
}
