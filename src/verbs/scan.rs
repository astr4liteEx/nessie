//! `nessie scan`: one `nessus-scan` per file: names, server preferences,
//! counts, and the scanner version from Nessus plugin 19506.

use crate::cli::{Args, Ctx};
use crate::nessus::{self, Host, Options, Policy, ReportItem, Visitor};
use crate::{jsonl, records};
use serde_json::{Map, Value, json};

/// Nessus Scan Information: the only place the scanner version is written.
const SCAN_INFO: u64 = 19506;

#[derive(Default)]
struct Summary {
    report: Option<String>,
    policy: Policy,
    hosts: u64,
    by_severity: [u64; 5],
    nessus_version: Option<String>,
    feed_version: Option<String>,
    saw_scan_info: bool,
}

impl Visitor for Summary {
    fn policy(&mut self, p: Policy) {
        self.policy = p;
    }

    fn report(&mut self, name: Option<&str>) {
        self.report = name.map(String::from);
    }

    fn host(&mut self, _: &Host) {
        self.hosts += 1;
    }

    fn item(&mut self, _: &Host, it: ReportItem) {
        self.by_severity[usize::from(it.severity.min(4))] += 1;
        if it.plugin_id == SCAN_INFO && !self.saw_scan_info {
            self.saw_scan_info = true;
            let out = it.plugin_output.unwrap_or_default();
            self.nessus_version = info_value(&out, "nessus version");
            self.feed_version = info_value(&out, "plugin feed version");
        }
    }
}

/// The value of a `Key : value` line in 19506's output. Keys are matched
/// without case (wording drifts between versions); a trailing note in
/// parentheses, such as "(Nessus 5.2.4 is available ...)", is dropped.
fn info_value(out: &str, key: &str) -> Option<String> {
    out.lines().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        if !k.trim().eq_ignore_ascii_case(key) {
            return None;
        }
        let v = v.trim();
        let v = v.split_once(" (").map_or(v, |(head, _)| head).trim();
        (!v.is_empty()).then(|| v.to_string())
    })
}

fn record(file: &str, s: Summary) -> Value {
    let mut m = Map::new();
    m.insert("kind".into(), "nessus-scan".into());
    m.insert("schema_version".into(), 1.into());
    m.insert("scan".into(), records::scan(file, s.report.as_deref()));
    if let Some(n) = &s.report {
        m.insert("name".into(), n.clone().into());
    }
    if let Some(p) = &s.policy.name {
        m.insert("policy_name".into(), p.clone().into());
    }
    let prefs: Map<String, Value> = s.policy.server_preferences.into_iter().map(|(k, v)| (k, v.into())).collect();
    m.insert("server_preferences".into(), Value::Object(prefs));
    m.insert("hosts".into(), s.hosts.into());
    let mut results = Map::new();
    results.insert("total".into(), json!(s.by_severity.iter().sum::<u64>()));
    for (sev, n) in s.by_severity.iter().enumerate() {
        results.insert(sev.to_string(), json!(n));
    }
    m.insert("results".into(), Value::Object(results));
    if let Some(v) = s.nessus_version {
        m.insert("nessus_version".into(), v.into());
    }
    if let Some(v) = s.feed_version {
        m.insert("feed_version".into(), v.into());
    }
    Value::Object(m)
}

pub fn run(args: &Args, ctx: &mut Ctx) -> i32 {
    let opts = Options { output: true, read_policy: true, ..Options::default() };
    super::each_scan(args, ctx, "scan", |name, src, w, diag| {
        let mut s = Summary::default();
        if !nessus::parse(src, name, &opts, &mut s, diag) {
            return true; // a broken file has no summary; go on to the next
        }
        jsonl::write_value(w, &record(name, s)).is_ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_version_lines_across_wordings() {
        let out = "Information about this scan : \n\n  Nessus version : 5.2.1 (Nessus 5.2.4 is available - consider upgrading)\n\
                   PLUGIN FEED VERSION : 201306260615\nScanner IP : 192.0.2.1\n";
        assert_eq!(info_value(out, "nessus version").as_deref(), Some("5.2.1"));
        assert_eq!(info_value(out, "plugin feed version").as_deref(), Some("201306260615"));
        assert_eq!(info_value(out, "nessus build"), None);
    }
}
