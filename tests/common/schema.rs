//! Validates records against `schema/`. Cross-file `$ref`s to
//! nessus-result.schema.json are inlined, so no registry is needed.

use serde_json::Value;
use std::collections::HashMap;
use std::sync::OnceLock;

fn load(kind: &str) -> Value {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/schema/");
    serde_json::from_str(&std::fs::read_to_string(format!("{dir}{kind}.schema.json")).unwrap()).unwrap()
}

fn inline(v: &mut Value) {
    match v {
        Value::Object(m) => {
            if let Some(Value::String(r)) = m.get_mut("$ref")
                && let Some(rest) = r.strip_prefix("nessus-result.schema.json")
            {
                *r = rest.to_string();
            }
            m.values_mut().for_each(inline);
        }
        Value::Array(a) => a.iter_mut().for_each(inline),
        _ => {}
    }
}

fn validators() -> &'static HashMap<String, jsonschema::Validator> {
    static V: OnceLock<HashMap<String, jsonschema::Validator>> = OnceLock::new();
    V.get_or_init(|| {
        let result = load("nessus-result");
        let defs = result["$defs"].clone();
        ["nessus-result", "nessus-item", "nessus-host", "nessus-scan", "nessus-service"]
            .into_iter()
            .map(|kind| {
                let mut s = load(kind);
                inline(&mut s);
                s.as_object_mut().unwrap().insert("$defs".into(), defs.clone());
                (kind.to_string(), jsonschema::validator_for(&s).unwrap())
            })
            .collect()
    })
}

/// Panics if a nessus-* record doesn't fit its schema. Other kinds pass.
pub fn validate(rec: &Value) {
    let kind = rec["kind"].as_str().unwrap_or_default();
    if let Some(v) = validators().get(kind) {
        let errs: Vec<String> = v.iter_errors(rec).map(|e| format!("{} at {}", e, e.instance_path())).collect();
        assert!(errs.is_empty(), "{kind} breaks its schema: {errs:?}\n{rec}");
    }
}
