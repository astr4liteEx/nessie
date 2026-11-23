//! `nessie help`: the built-in verbs, then the extensions on PATH, as rpt
//! `command` records. `nessie help <verb>` prints that verb's help.

use crate::cli::{self, Args, Ctx};
use crate::diag::Loc;
use crate::{ext, jsonl};
use serde_json::{Map, Value};

/// The members of a `--describe` answer a command record carries.
const DESCRIBED: [&str; 6] = ["summary", "usage", "version", "input", "output", "roles"];

fn builtin_record(v: &cli::Verb) -> Value {
    let mut m = Map::new();
    m.insert("kind".into(), "command".into());
    m.insert("name".into(), v.name.into());
    m.insert("source".into(), "builtin".into());
    if let Value::Object(d) = cli::describe(v) {
        // A built-in's version is nessie's: rpt leaves it to plugins.
        m.extend(d.into_iter().filter(|(k, _)| k != "version"));
    }
    Value::Object(m)
}

pub fn run(args: &Args, ctx: &mut Ctx) -> i32 {
    match args.positional.as_slice() {
        [] => {}
        [name] => return help_for(name, ctx),
        _ => return super::usage(ctx, "help", "give one verb, or none"),
    }
    let mut recs: Vec<Value> = super::ALL.iter().map(builtin_record).collect();
    for (name, path) in ext::discover() {
        let mut m = Map::new();
        m.insert("kind".into(), "command".into());
        m.insert("name".into(), name.clone().into());
        m.insert("source".into(), "extension".into());
        m.insert("path".into(), path.to_string_lossy().into_owned().into());
        if super::find(&name).is_some() {
            m.insert("shadowed".into(), true.into());
        }
        match ext::describe(&path) {
            Ok(d) => {
                for k in DESCRIBED {
                    if let Some(v) = d.get(k) {
                        m.insert(k.into(), v.clone());
                    }
                }
            }
            Err(e) => ctx.diag.warning(Loc::none(), format!("extension {name}: {e}")),
        }
        recs.push(Value::Object(m));
    }
    for r in recs {
        if jsonl::write_value(ctx.stdout, &r).is_err() {
            break;
        }
    }
    ctx.diag.code()
}

fn help_for(name: &str, ctx: &mut Ctx) -> i32 {
    if let Some(v) = super::find(name) {
        let _ = ctx.stdout.write_all(cli::help(v).as_bytes());
        return ctx.diag.code();
    }
    let Some(path) = ext::lookup(name) else {
        return super::usage(ctx, "help", &format!("no verb or extension named {name}"));
    };
    match std::process::Command::new(&path).arg("--help").env("NESSIE_BIN", ext::self_path()).output() {
        Ok(o) => {
            let _ = ctx.stdout.write_all(&o.stdout);
            if !o.status.success() {
                ctx.diag.error(Loc::none(), format!("{} --help failed ({})", path.display(), o.status));
            }
        }
        Err(e) => ctx.diag.error(Loc::none(), format!("{}: can't run: {e}", path.display())),
    }
    ctx.diag.code()
}
