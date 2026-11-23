//! `nessie items`: Results grouped by Nessus plugin, one `nessus-item` each.

use crate::cli::{Args, Ctx};
use crate::diag::{Diag, Loc};
use crate::jsonl::{self, MAX_LINE};
use crate::stream::{self, Ev, ResultRec};
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};

/// One Item being built.
struct Group {
    plugin_id: u64,
    plugin_name: String,
    plugin_family: String,
    severity: u8,
    scans: Vec<Value>,
    /// Element name -> values in first-seen order, with a set to de-duplicate.
    elements: Vec<(String, Vec<String>, HashSet<String>)>,
    hosts: Vec<(Value, Vec<Value>)>,
    host_index: HashMap<String, usize>,
}

impl Group {
    fn new(r: &ResultRec) -> Self {
        Self {
            plugin_id: r.plugin_id(),
            plugin_name: r.str("plugin_name").to_string(),
            plugin_family: r.str("plugin_family").to_string(),
            severity: 0,
            scans: Vec::new(),
            elements: Vec::new(),
            hosts: Vec::new(),
            host_index: HashMap::new(),
        }
    }

    fn add(&mut self, r: ResultRec) {
        self.severity = self.severity.max(r.severity());
        if !self.scans.contains(r.scan()) {
            self.scans.push(r.scan().clone());
        }
        for (name, values) in r.elements() {
            let i = match self.elements.iter().position(|(n, _, _)| n == name) {
                Some(i) => i,
                None => {
                    self.elements.push((name.clone(), Vec::new(), HashSet::new()));
                    self.elements.len() - 1
                }
            };
            let (_, list, seen) = &mut self.elements[i];
            for v in values.as_array().into_iter().flatten().filter_map(Value::as_str) {
                if seen.insert(v.to_string()) {
                    list.push(v.to_string());
                }
            }
        }
        let mut ep = Map::new();
        ep.insert("port".into(), r.port().into());
        ep.insert("protocol".into(), r.str("protocol").into());
        ep.insert("svc_name".into(), r.str("svc_name").into());
        ep.insert("severity".into(), r.severity().into());
        if let Some(o) = r.output() {
            ep.insert("plugin_output".into(), o.into());
        }
        let key = r.host().to_string();
        let i = *self.host_index.entry(key).or_insert_with(|| {
            self.hosts.push((r.host().clone(), Vec::new()));
            self.hosts.len() - 1
        });
        self.hosts[i].1.push(Value::Object(ep));
    }

    /// The record without its hosts.
    fn head(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("kind".into(), "nessus-item".into());
        m.insert("schema_version".into(), 1.into());
        m.insert("scan".into(), Value::Array(self.scans.clone()));
        m.insert("plugin_id".into(), self.plugin_id.into());
        m.insert("plugin_name".into(), self.plugin_name.clone().into());
        m.insert("plugin_family".into(), self.plugin_family.clone().into());
        m.insert("severity".into(), self.severity.into());
        let els: Map<String, Value> = self.elements.iter().map(|(n, list, _)| (n.clone(), json!(list))).collect();
        m.insert("elements".into(), Value::Object(els));
        m
    }
}

fn host_entry(host: &Value, endpoints: &[Value]) -> Value {
    json!({"host": host, "endpoints": endpoints})
}

fn size(v: &Value) -> usize {
    serde_json::to_vec(v).map(|b| b.len()).unwrap_or(usize::MAX)
}

/// The records for one Item: one, or several parts when a single line would
/// pass `max` bytes. A Host whose entry alone passes it loses its
/// plugin_output, with an error.
fn item_records(g: Group, max: usize, diag: &mut Diag) -> Vec<Value> {
    let head = g.head();
    let mut entries: Vec<Value> = Vec::with_capacity(g.hosts.len());
    for (host, mut eps) in g.hosts {
        let mut entry = host_entry(&host, &eps);
        // Room for the head, the part member and the brackets around hosts.
        if size(&entry) + size(&Value::Object(head.clone())) + 64 > max {
            for ep in &mut eps {
                if let Some(o) = ep.as_object_mut() {
                    o.shift_remove("plugin_output");
                }
            }
            entry = host_entry(&host, &eps);
            diag.error(
                Loc::none(),
                format!(
                    "Nessus plugin {}: the output on Host {} alone passes {} MiB, so it was left out",
                    g.plugin_id,
                    host,
                    max / (1024 * 1024)
                ),
            );
        }
        entries.push(entry);
    }
    let whole = |hosts: Vec<Value>| {
        let mut m = head.clone();
        m.insert("hosts".into(), Value::Array(hosts));
        m
    };
    let one = whole(entries.clone());
    if size(&Value::Object(one.clone())) <= max {
        return vec![Value::Object(one)];
    }
    // Pack whole Hosts into parts, in order.
    let base = size(&Value::Object(whole(Vec::new()))) + 64;
    let mut parts: Vec<Vec<Value>> = vec![Vec::new()];
    let mut used = base;
    for e in entries {
        let n = size(&e) + 1;
        if used + n > max && !parts.last().unwrap().is_empty() {
            parts.push(Vec::new());
            used = base;
        }
        used += n;
        parts.last_mut().unwrap().push(e);
    }
    let count = parts.len();
    parts
        .into_iter()
        .enumerate()
        .map(|(i, hosts)| {
            let mut m = whole(hosts);
            m.insert("part".into(), json!({"index": i + 1, "count": count}));
            Value::Object(m)
        })
        .collect()
}

pub fn run(args: &Args, ctx: &mut Ctx) -> i32 {
    run_with_max(args, ctx, MAX_LINE)
}

/// `run` with the line cap as a parameter, so tests can force a split.
pub fn run_with_max(args: &Args, ctx: &mut Ctx, max: usize) -> i32 {
    let opts = match super::parse_options(args) {
        Ok(o) => o,
        Err(e) => return super::usage(ctx, "items", &e),
    };
    let mut groups: Vec<Group> = Vec::new();
    let mut index: HashMap<u64, usize> = HashMap::new();
    let mut closed = false;
    let code = super::each_input(args, ctx, "items", |name, src, format, w, diag| {
        let mut on = |ev: Ev| {
            match ev {
                Ev::Result(r) => {
                    let i = *index.entry(r.plugin_id()).or_insert_with(|| {
                        groups.push(Group::new(&r));
                        groups.len() - 1
                    });
                    groups[i].add(r);
                }
                Ev::Pass(raw) => {
                    if jsonl::write_raw(w, &raw).is_err() {
                        closed = true;
                    }
                }
                Ev::Host(_) => {}
            }
            !closed
        };
        stream::read(name, src, format, &opts, diag, &mut on);
        !closed
    });
    if closed {
        return code;
    }
    for g in groups {
        for rec in item_records(g, max, &mut ctx.diag) {
            if jsonl::write_value(ctx.stdout, &rec).is_err() {
                return ctx.diag.code();
            }
        }
    }
    ctx.diag.code()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(host: &str, out: &str) -> ResultRec {
        let v = json!({"kind":"nessus-result","schema_version":1,"scan":{"file":"f"},"host":{"name":host},
            "port":22,"protocol":"tcp","svc_name":"ssh","severity":1,"plugin_id":22869,"plugin_name":"n",
            "plugin_family":"f","elements":{"cve":["A"]},"plugin_output":out});
        ResultRec::check(v.as_object().unwrap().clone()).unwrap()
    }

    fn group(hosts: &[(&str, usize)]) -> Group {
        let mut g = Group::new(&result("x", ""));
        for (h, n) in hosts {
            g.add(result(h, &"o".repeat(*n)));
        }
        g
    }

    #[test]
    fn splits_into_parts_of_whole_hosts_and_merging_them_restores_the_item() {
        let mut err = Vec::new();
        let mut d = Diag::new(&mut err);
        let recs = item_records(group(&[("a", 300), ("b", 300), ("c", 300)]), 900, &mut d);
        assert!(!d.failed());
        assert!(recs.len() >= 2, "{recs:?}");
        let mut hosts = Vec::new();
        for (i, r) in recs.iter().enumerate() {
            assert!(size(r) <= 900);
            assert_eq!(r["part"], json!({"index": i + 1, "count": recs.len()}));
            hosts.extend(r["hosts"].as_array().unwrap().iter().map(|h| h["host"]["name"].clone()));
        }
        assert_eq!(hosts, vec![json!("a"), json!("b"), json!("c")]);
    }

    #[test]
    fn an_item_that_fits_has_no_part() {
        let mut err = Vec::new();
        let mut d = Diag::new(&mut err);
        let recs = item_records(group(&[("a", 10)]), MAX_LINE, &mut d);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].get("part").is_none());
    }

    #[test]
    fn a_host_too_big_alone_loses_its_output_with_an_error() {
        let mut err = Vec::new();
        let recs = {
            let mut d = Diag::new(&mut err);
            let r = item_records(group(&[("a", 2000), ("b", 10)]), 900, &mut d);
            assert!(d.failed());
            r
        };
        let all: Vec<&Value> = recs.iter().flat_map(|r| r["hosts"].as_array().unwrap()).collect();
        assert!(all[0]["endpoints"][0].get("plugin_output").is_none());
        assert!(all[1]["endpoints"][0].get("plugin_output").is_some());
        assert!(String::from_utf8(err).unwrap().contains("Nessus plugin 22869"));
    }
}
