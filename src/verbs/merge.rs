//! `nessie merge`: Results from several scans de-duplicated, the later scan
//! winning the whole record.
//!
//! Each record's `scan` member is its unit: a key repeated within one scan
//! is kept (Nessus does write duplicates), and a later scan with the key
//! replaces every earlier record with it. Inputs, and scans within a stream,
//! are taken in the order they appear: list scans oldest first.

use crate::cli::{Args, Ctx};
use crate::identity::{Hosts, Key};
use crate::jsonl;
use crate::stream::{self, Ev, ResultRec};
use serde_json::Value;
use std::collections::HashMap;

pub fn run(args: &Args, ctx: &mut Ctx) -> i32 {
    let opts = match super::parse_options(args) {
        Ok(o) => o,
        Err(e) => return super::usage(ctx, "merge", &e),
    };
    let mut hosts = Hosts::default();
    // Key -> (the scan its records came from, the records). `order` keeps
    // the keys in first-seen order for the output.
    let mut kept: HashMap<Key, (String, Vec<ResultRec>)> = HashMap::new();
    let mut order: Vec<Key> = Vec::new();
    let mut closed = false;
    let code = super::each_input(args, ctx, "merge", |name, src, format, w, diag| {
        let mut on = |ev: Ev| {
            match ev {
                Ev::Result(r) => {
                    let key = (hosts.id(r.host()), r.plugin_id(), r.port(), r.str("protocol").to_string());
                    let scan = r.scan().to_string();
                    match kept.get_mut(&key) {
                        Some((s, recs)) if *s == scan => recs.push(r),
                        Some(slot) => *slot = (scan, vec![r]),
                        None => {
                            order.push(key.clone());
                            kept.insert(key, (scan, vec![r]));
                        }
                    }
                }
                Ev::Pass(raw) => closed |= jsonl::write_raw(w, &raw).is_err(),
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
    for key in order {
        let (_, recs) = kept.remove(&key).expect("every ordered key is kept");
        for r in recs {
            if jsonl::write_value(ctx.stdout, &Value::Object(r.obj)).is_err() {
                return ctx.diag.code();
            }
        }
    }
    ctx.diag.code()
}
