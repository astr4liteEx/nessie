//! `nessie hosts`: one `nessus-host` per ReportHost, with every
//! HostProperties tag and its Result counts.

use crate::cli::{Args, Ctx};
use crate::nessus::{self, Host, Options, ReportItem, Visitor};
use crate::{jsonl, records};
use serde_json::{Map, Value};
use std::io::Write;

struct Out<'w> {
    w: &'w mut dyn Write,
    file: String,
    scan: Value,
    by_severity: [u64; 5],
    closed: bool,
}

impl Visitor for Out<'_> {
    fn report(&mut self, name: Option<&str>) {
        self.scan = records::scan(&self.file, name);
    }

    fn host(&mut self, _: &Host) {
        self.by_severity = [0; 5];
    }

    fn item(&mut self, _: &Host, it: ReportItem) {
        self.by_severity[usize::from(it.severity.min(4))] += 1;
    }

    fn below(&mut self, _: &Host, severity: u8) {
        self.by_severity[usize::from(severity.min(4))] += 1;
    }

    fn host_end(&mut self, h: &Host) {
        let mut props = Map::new();
        for (k, v) in &h.properties {
            props.insert(k.clone(), v.clone().into());
        }
        let mut m = Map::new();
        m.insert("kind".into(), "nessus-host".into());
        m.insert("schema_version".into(), 1.into());
        m.insert("scan".into(), self.scan.clone());
        m.insert("host".into(), records::host(h));
        m.insert("properties".into(), Value::Object(props));
        m.insert("results".into(), records::counts(&self.by_severity));
        if jsonl::write_value(self.w, &Value::Object(m)).is_err() {
            self.closed = true;
        }
    }

    fn stop(&self) -> bool {
        self.closed
    }
}

pub fn run(args: &Args, ctx: &mut Ctx) -> i32 {
    // Every Result is below this, so each is only counted, never read.
    let opts = Options { min_severity: Some(u8::MAX), ..Options::default() };
    super::each_scan(args, ctx, "hosts", |name, src, w, diag| {
        let mut out =
            Out { w, file: name.to_string(), scan: records::scan(name, None), by_severity: [0; 5], closed: false };
        nessus::parse(src, name, &opts, &mut out, diag);
        !out.closed
    })
}
