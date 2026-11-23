//! `nessie hosts`: one `nessus-host` per ReportHost, with every
//! HostProperties tag.

use crate::cli::{Args, Ctx};
use crate::nessus::{self, Host, Options, Visitor};
use crate::{jsonl, records};
use serde_json::{Map, Value};
use std::io::Write;

struct Out<'w> {
    w: &'w mut dyn Write,
    file: String,
    scan: Value,
    closed: bool,
}

impl Visitor for Out<'_> {
    fn report(&mut self, name: Option<&str>) {
        self.scan = records::scan(&self.file, name);
    }

    fn host(&mut self, h: &Host) {
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
        if jsonl::write_value(self.w, &Value::Object(m)).is_err() {
            self.closed = true;
        }
    }

    fn stop(&self) -> bool {
        self.closed
    }
}

pub fn run(args: &Args, ctx: &mut Ctx) -> i32 {
    // Results are skipped: everything a Host record needs comes before them.
    let opts = Options { min_severity: Some(u8::MAX), ..Options::default() };
    super::each_scan(args, ctx, "hosts", |name, src, w, diag| {
        let mut out = Out { w, file: name.to_string(), scan: records::scan(name, None), closed: false };
        nessus::parse(src, name, &opts, &mut out, diag);
        !out.closed
    })
}
