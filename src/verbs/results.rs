//! `nessie results`: one `nessus-result` per ReportItem, the base stream.

use crate::cli::{Args, Ctx};
use crate::nessus::{self, Host, ReportItem, Visitor};
use crate::{jsonl, records};
use serde_json::Value;
use std::io::Write;

struct Out<'w> {
    w: &'w mut dyn Write,
    file: String,
    scan: Value,
    host: Value,
    closed: bool,
}

impl Visitor for Out<'_> {
    fn report(&mut self, name: Option<&str>) {
        self.scan = records::scan(&self.file, name);
    }

    fn host(&mut self, h: &Host) {
        self.host = records::host(h);
    }

    fn item(&mut self, _: &Host, it: ReportItem) {
        if jsonl::write_value(self.w, &records::result(&self.scan, &self.host, it)).is_err() {
            self.closed = true;
        }
    }

    fn stop(&self) -> bool {
        self.closed
    }
}

pub fn run(args: &Args, ctx: &mut Ctx) -> i32 {
    let opts = match super::parse_options(args) {
        Ok(o) => o,
        Err(e) => return super::usage(ctx, "results", &e),
    };
    super::each_scan(args, ctx, "results", |name, src, w, diag| {
        let mut out =
            Out { w, file: name.to_string(), scan: records::scan(name, None), host: Value::Null, closed: false };
        nessus::parse(src, name, &opts, &mut out, diag);
        !out.closed
    })
}
