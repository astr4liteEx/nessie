//! `nessie diff <old> <new>`: each Result marked new, fixed, present or
//! host-missing.
//!
//! The old side is held in memory, keyed; the new side streams. new and
//! present Results print as the new side arrives (the new record), then
//! fixed and host-missing ones (the old record). A Host is in an input if
//! the scan has a ReportHost for it (before --min-severity), or, for a
//! records stream, if any Result names it.

use crate::cli::{Args, Ctx};
use crate::diag::{Diag, Loc};
use crate::identity::{Hosts, Key};
use crate::inputs::{self, Format};
use crate::jsonl;
use crate::nessus::Options;
use crate::stream::{self, Ev, ResultRec};
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{BufRead, Write};

/// What `changed` can name, in this order.
const COMPARED: [&str; 4] = ["severity", "plugin_name", "elements", "plugin_output"];

fn changed(old: &ResultRec, new: &ResultRec) -> Vec<&'static str> {
    COMPARED
        .into_iter()
        .filter(|k| match (old.obj.get(*k), new.obj.get(*k)) {
            // plugin_output counts only when both sides have it.
            (None, _) | (_, None) if *k == "plugin_output" => false,
            (a, b) => a != b,
        })
        .collect()
}

fn marked(r: ResultRec, state: &str, changes: Option<Vec<&str>>) -> Value {
    let mut obj: Map<String, Value> = r.obj;
    let mut d = Map::new();
    d.insert("state".into(), state.into());
    if let Some(c) = changes {
        d.insert("changed".into(), json!(c));
    }
    obj.insert("diff".into(), Value::Object(d));
    Value::Object(obj)
}

/// Opens and sniffs one side, then reads it with `on`.
fn read_side(
    name: &str,
    stdin: &mut dyn BufRead,
    opts: &Options,
    diag: &mut Diag,
    on: &mut dyn FnMut(Ev) -> bool,
) -> bool {
    let mut src = match inputs::open(name, stdin) {
        Ok(s) => s,
        Err(e) => {
            diag.error(Loc::path(name), format!("can't read: {e}"));
            return false;
        }
    };
    match inputs::sniff(&mut src) {
        Ok(Format::Other(_)) => {
            diag.error(Loc::path(name), "neither a .nessus scan nor JSON Lines");
            false
        }
        Ok(format) => stream::read(name, &mut src, format, opts, diag, on),
        Err(e) => {
            diag.error(Loc::path(name), format!("can't read: {e}"));
            false
        }
    }
}

pub fn run(args: &Args, ctx: &mut Ctx) -> i32 {
    let opts = match super::parse_options(args) {
        Ok(o) => o,
        Err(e) => return super::usage(ctx, "diff", &e),
    };
    let [old_name, new_name] = args.positional.as_slice() else {
        return super::usage(ctx, "diff", "give two inputs: <old> <new>");
    };
    if old_name == "-" && new_name == "-" {
        return super::usage(ctx, "diff", "stdin can be read once: give - at most once");
    }

    // The old side, keyed.
    let mut hosts = Hosts::default();
    let mut old: Vec<Option<ResultRec>> = Vec::new();
    let mut old_host: Vec<usize> = Vec::new();
    let mut by_key: HashMap<Key, VecDeque<usize>> = HashMap::new();
    let mut closed = false;
    let out: &mut dyn Write = &mut *ctx.stdout;
    let ok = read_side(old_name, &mut *ctx.stdin, &opts, &mut ctx.diag, &mut |ev| {
        match ev {
            Ev::Host(h) => {
                hosts.id(&h);
            }
            Ev::Result(r) => {
                let id = hosts.id(r.host());
                by_key
                    .entry((id, r.plugin_id(), r.port(), r.str("protocol").to_string()))
                    .or_default()
                    .push_back(old.len());
                old_host.push(id);
                old.push(Some(r));
            }
            Ev::Pass(raw) => closed |= jsonl::write_raw(out, &raw).is_err(),
        }
        !closed
    });
    if !ok || closed {
        return ctx.diag.code();
    }

    // The new side, streamed against it.
    let mut seen_hosts: HashSet<usize> = HashSet::new();
    let ok = read_side(new_name, &mut *ctx.stdin, &opts, &mut ctx.diag, &mut |ev| {
        match ev {
            Ev::Host(h) => {
                if let Some(id) = hosts.find(&h) {
                    seen_hosts.insert(id);
                }
            }
            Ev::Result(r) => {
                let id = hosts.find(r.host());
                if let Some(id) = id {
                    seen_hosts.insert(id);
                }
                let paired = id.and_then(|id| {
                    by_key.get_mut(&(id, r.plugin_id(), r.port(), r.str("protocol").to_string()))?.pop_front()
                });
                let rec = match paired.and_then(|i| old[i].take()) {
                    Some(o) => {
                        let c = changed(&o, &r);
                        marked(r, "present", Some(c))
                    }
                    None => marked(r, "new", None),
                };
                closed |= jsonl::write_value(out, &rec).is_err();
            }
            Ev::Pass(raw) => closed |= jsonl::write_raw(out, &raw).is_err(),
        }
        !closed
    });
    if !ok || closed {
        return ctx.diag.code();
    }

    for (i, rec) in old.into_iter().enumerate() {
        let Some(r) = rec else { continue };
        let state = if seen_hosts.contains(&old_host[i]) { "fixed" } else { "host-missing" };
        if jsonl::write_value(ctx.stdout, &marked(r, state, None)).is_err() {
            break;
        }
    }
    ctx.diag.code()
}
