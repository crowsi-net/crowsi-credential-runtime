use serde_json::Value;

use crate::{USE_RECEIPT_SCHEMA, USE_REQUEST_SCHEMA, UseReceiptV1, UseRequestV1};

#[test]
fn published_schema_ids_match_the_closed_rust_contracts() {
    let request: Value =
        serde_json::from_str(include_str!("../schemas/use-request-v1.schema.json"))
            .expect("request schema");
    let receipt: Value =
        serde_json::from_str(include_str!("../schemas/use-receipt-v1.schema.json"))
            .expect("receipt schema");
    let audit: Value = serde_json::from_str(include_str!("../schemas/audit-event-v1.schema.json"))
        .expect("audit schema");
    assert_eq!(request["$id"], USE_REQUEST_SCHEMA);
    assert_eq!(receipt["$id"], USE_RECEIPT_SCHEMA);
    assert_eq!(audit["$id"], crate::audit::AUDIT_EVENT_SCHEMA);
}

#[test]
fn fixtures_reject_unknown_fields() {
    let mut request: Value =
        serde_json::from_str(include_str!("../fixtures/aws-sign-use-request-v1.json"))
            .expect("request fixture");
    request["legacy"] = Value::Bool(true);
    assert!(serde_json::from_value::<UseRequestV1>(request).is_err());

    let mut receipt: Value =
        serde_json::from_str(include_str!("../fixtures/aws-sign-use-receipt-v1.json"))
            .expect("receipt fixture");
    receipt["legacy"] = Value::Bool(true);
    assert!(serde_json::from_value::<UseReceiptV1>(receipt).is_err());
}

#[test]
fn client_rejects_tampered_output_schema_and_payload() {
    let request: UseRequestV1 =
        serde_json::from_str(include_str!("../fixtures/aws-sign-use-request-v1.json"))
            .expect("request fixture");
    let source: Value =
        serde_json::from_str(include_str!("../fixtures/aws-sign-use-receipt-v1.json"))
            .expect("receipt fixture");
    let mut wrong_schema = source.clone();
    wrong_schema["output"]["schema"] = Value::String("zixcel://aws/other/v1".into());
    let receipt: UseReceiptV1 = serde_json::from_value(wrong_schema).expect("receipt");
    assert!(receipt.validate_for(&request).is_err());

    let mut wrong_payload = source;
    wrong_payload["output"]["payload"][0] = Value::from(0);
    let receipt: UseReceiptV1 = serde_json::from_value(wrong_payload).expect("receipt");
    assert!(receipt.validate_for(&request).is_err());
}
