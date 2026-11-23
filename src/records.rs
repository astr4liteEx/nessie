//! Building nessie's records from parsed scan parts, in the member order the
//! schemas in `schema/` list.

use crate::nessus::{Host, ReportItem};
use serde_json::{Map, Value, json};

/// The `scan` member: which file a record came from.
pub fn scan(file: &str, name: Option<&str>) -> Value {
    let mut m = Map::new();
    m.insert("file".into(), file.into());
    if let Some(n) = name {
        m.insert("name".into(), n.into());
    }
    Value::Object(m)
}

/// The `host` member: the Host's identity as the scan gives it.
pub fn host(h: &Host) -> Value {
    let mut m = Map::new();
    m.insert("name".into(), h.name.clone().into());
    if let Some(ip) = h.ip() {
        m.insert("ip".into(), ip.into());
    }
    if let Some(fqdn) = h.fqdn() {
        m.insert("fqdn".into(), fqdn.into());
    }
    Value::Object(m)
}

/// The `elements` member.
pub fn elements(els: Vec<(String, Vec<String>)>) -> Value {
    Value::Object(els.into_iter().map(|(k, v)| (k, json!(v))).collect())
}

/// A `nessus-result` record.
pub fn result(scan: &Value, host: &Value, it: ReportItem) -> Value {
    let mut m = Map::new();
    m.insert("kind".into(), "nessus-result".into());
    m.insert("schema_version".into(), 1.into());
    m.insert("scan".into(), scan.clone());
    m.insert("host".into(), host.clone());
    m.insert("port".into(), it.port.into());
    m.insert("protocol".into(), it.protocol.into());
    m.insert("svc_name".into(), it.svc_name.into());
    m.insert("severity".into(), it.severity.into());
    m.insert("plugin_id".into(), it.plugin_id.into());
    m.insert("plugin_name".into(), it.plugin_name.into());
    m.insert("plugin_family".into(), it.plugin_family.into());
    m.insert("elements".into(), elements(it.elements));
    if let Some(o) = it.plugin_output {
        m.insert("plugin_output".into(), o.into());
    }
    Value::Object(m)
}

/// Result counts by severity, keyed "0" to "4", after their total.
pub fn counts(by_severity: &[u64; 5]) -> Value {
    let mut m = Map::new();
    m.insert("total".into(), by_severity.iter().sum::<u64>().into());
    for (sev, n) in by_severity.iter().enumerate() {
        m.insert(sev.to_string(), (*n).into());
    }
    Value::Object(m)
}
