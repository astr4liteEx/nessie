//! `nessie results`: one `nessus-result` per ReportItem, the base stream.

use crate::cli::{Args, Ctx};
use crate::diag::Loc;
use crate::nessus::{self, Host, ReportItem, Visitor};
use crate::{inputs, jsonl, records};
use serde_json::Value;
use std::io::Write;

struct Out<'w> {
    w: &'w mut dyn Write,
    scan: Value,
    host: Value,
    closed: bool,
}

impl Visitor for Out<'_> {
    fn report(&mut self, name: Option<&str>) {
        let file = self.scan["file"].as_str().unwrap_or("-").to_string();
        self.scan = records::scan(&file, name);
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
    let names = match inputs::names(&args.positional, ctx) {
        Ok(n) => n,
        Err(e) => return super::usage(ctx, "results", &e),
    };
    for name in &names {
        let src = match inputs::open(name, ctx.stdin) {
            Ok(s) => s,
            Err(e) => {
                ctx.diag.error(Loc::path(name), format!("can't read: {e}"));
                continue;
            }
        };
        let mut out = Out { w: ctx.stdout, scan: records::scan(name, None), host: Value::Null, closed: false };
        nessus::parse(src, name, &opts, &mut out, &mut ctx.diag);
        if out.closed {
            break;
        }
    }
    ctx.diag.code()
}
