//! The command line: the verb table, flag parsing, `--describe` and `--help`.
//!
//! Flags are GNU-style and may follow arguments: `--flag`, `--flag value`,
//! `--flag=value`, `-h`; `--` ends the flags and `-` is an argument (stdin).

use crate::diag::{Diag, Loc};
use crate::{Io, VERSION, exit, verbs};
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// Whether a flag takes a value.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Arity {
    Bool,
    Value,
}

pub struct Flag {
    pub name: &'static str,
    pub arity: Arity,
    /// Shown in help after the flag, for a flag that takes a value.
    pub value: &'static str,
    pub help: &'static str,
}

pub const OUTPUT: Flag =
    Flag { name: "output", arity: Arity::Bool, value: "", help: "Include each Result's plugin_output" };
pub const MIN_SEVERITY: Flag = Flag {
    name: "min-severity",
    arity: Arity::Value,
    value: "N",
    help: "Drop Results below severity N (0-4) while parsing. Nessus 4.2 marks informational Results 1",
};
const JSON: Flag = Flag { name: "json", arity: Arity::Bool, value: "", help: "Print JSON Lines even on a terminal" };
const HELP: Flag = Flag { name: "help", arity: Arity::Bool, value: "", help: "Show this help" };

/// A built-in verb and how it describes itself.
pub struct Verb {
    pub name: &'static str,
    pub summary: &'static str,
    pub usage: &'static str,
    pub input: Option<&'static str>,
    pub output: Option<&'static str>,
    pub roles: &'static [&'static str],
    pub flags: &'static [Flag],
    /// Extra help text after the flags.
    pub notes: &'static str,
    pub run: fn(&Args, &mut Ctx) -> i32,
}

/// What a verb runs with: the streams, and stderr wrapped as a Diag.
pub struct Ctx<'a> {
    pub stdin: &'a mut dyn std::io::BufRead,
    pub stdout: &'a mut dyn std::io::Write,
    pub diag: Diag<'a>,
    pub stdin_tty: bool,
    pub stdout_tty: bool,
    pub style: crate::table::Style,
}

/// A verb's parsed command line.
pub struct Args {
    flags: BTreeMap<&'static str, Vec<String>>,
    pub positional: Vec<String>,
}

impl Args {
    pub fn has(&self, name: &str) -> bool {
        self.flags.contains_key(name)
    }

    /// The last value given for a flag.
    pub fn value(&self, name: &str) -> Option<&str> {
        self.flags.get(name).and_then(|v| v.last()).map(String::as_str)
    }

    /// True when output should be JSON Lines rather than a table.
    pub fn json(&self, ctx: &Ctx) -> bool {
        self.has("json") || !ctx.stdout_tty
    }
}

/// Parses `args` against a verb's flags plus the global ones.
pub fn parse(verb: &Verb, args: &[String]) -> Result<Args, String> {
    let mut out = Args { flags: BTreeMap::new(), positional: Vec::new() };
    let mut it = args.iter();
    let find = |name: &str| verb.flags.iter().chain([&JSON, &HELP]).find(|f| f.name == name);
    while let Some(a) = it.next() {
        if a == "--" {
            out.positional.extend(it.by_ref().cloned());
            break;
        }
        if a == "-h" {
            out.flags.entry("help").or_default();
            continue;
        }
        let Some(body) = a.strip_prefix("--") else {
            if a.len() > 1 && a.starts_with('-') {
                return Err(format!("unknown flag {a}"));
            }
            out.positional.push(a.clone());
            continue;
        };
        let (name, inline) = match body.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (body, None),
        };
        let flag = find(name).ok_or_else(|| format!("unknown flag --{name}"))?;
        let value = match (flag.arity, inline) {
            (Arity::Bool, None) => String::new(),
            (Arity::Bool, Some(_)) => return Err(format!("--{name} takes no value")),
            (Arity::Value, Some(v)) => v,
            (Arity::Value, None) => it.next().cloned().ok_or_else(|| format!("--{name} needs a value"))?,
        };
        out.flags.entry(flag.name).or_default().push(value);
    }
    Ok(out)
}

/// The tool's own `--describe` answer.
pub fn describe_tool() -> Value {
    json!({
        "summary": "Read Nessus scans and emit what is in them as records",
        "usage": "nessie <verb> [flags] [scan.nessus...]",
        "version": VERSION,
        "input": "xml/nessus",
        "output": "records",
        "roles": ["source", "filter"],
    })
}

/// A verb's `--describe` answer.
pub fn describe(v: &Verb) -> Value {
    let mut d = serde_json::Map::new();
    d.insert("summary".into(), v.summary.into());
    d.insert("usage".into(), v.usage.into());
    d.insert("version".into(), VERSION.into());
    if let Some(i) = v.input {
        d.insert("input".into(), i.into());
    }
    if let Some(o) = v.output {
        d.insert("output".into(), o.into());
    }
    if !v.roles.is_empty() {
        d.insert("roles".into(), json!(v.roles));
    }
    Value::Object(d)
}

/// A verb's `--help` text.
pub fn help(v: &Verb) -> String {
    let mut s = format!("{}\n\nUsage: {}\n\nFlags:\n", v.summary, v.usage);
    for f in v.flags.iter().chain([&JSON, &HELP]) {
        let left = match (f.name, f.arity) {
            ("help", _) => "-h, --help".to_string(),
            (n, Arity::Value) => format!("--{n} {}", f.value),
            (n, Arity::Bool) => format!("--{n}"),
        };
        s.push_str(&format!("  {left:<20}{}\n", f.help));
    }
    if !v.notes.is_empty() {
        s.push('\n');
        s.push_str(v.notes);
        if !v.notes.ends_with('\n') {
            s.push('\n');
        }
    }
    s
}

/// The tool's `--help` text: the built-in verbs.
fn tool_help() -> String {
    let mut s = String::from(
        "nessie reads Nessus scans and emits what is in them as JSON Lines records.\n\n\
         Usage: nessie <verb> [flags] [scan.nessus...]\n\nVerbs:\n",
    );
    for v in verbs::ALL {
        s.push_str(&format!("  {:<10}{}\n", v.name, v.summary));
    }
    s.push_str(
        "\nRun `nessie <verb> --help` for a verb's flags. Any other verb runs the extension\n\
         nessie-<verb> from PATH. Chains should run with `set -o pipefail`.\n",
    );
    s
}

fn print(io: &mut Io, text: &str) -> i32 {
    match io.stdout.write_all(text.as_bytes()) {
        Ok(()) => exit::OK,
        Err(_) => exit::PROBLEMS,
    }
}

fn print_json(io: &mut Io, v: &Value) -> i32 {
    match crate::jsonl::write_value(io.stdout, v) {
        Ok(()) => exit::OK,
        Err(_) => exit::PROBLEMS,
    }
}

pub fn run(args: &[String], io: &mut Io) -> i32 {
    let Some(first) = args.first() else {
        let _ = io.stderr.write_all(tool_help().as_bytes());
        return exit::USAGE;
    };
    match first.as_str() {
        "--describe" if args.len() == 1 => return print_json(io, &describe_tool()),
        "--help" | "-h" => return print(io, &tool_help()),
        "--version" => return run(&["version".to_string()], io),
        _ => {}
    }
    let rest = &args[1..];
    let Some(verb) = verbs::find(first) else {
        let mut d = Diag::new(io.stderr);
        d.error(Loc::none(), format!("unknown verb {first}: run `nessie --help` for the list"));
        return exit::USAGE;
    };
    if rest.len() == 1 && rest[0] == "--describe" {
        return print_json(io, &describe(verb));
    }
    let parsed = match parse(verb, rest) {
        Ok(p) => p,
        Err(e) => {
            let mut d = Diag::new(io.stderr);
            d.error(Loc::none(), format!("{}: {e}", verb.name));
            let _ = writeln!(io.stderr, "usage: {}", verb.usage);
            return exit::USAGE;
        }
    };
    if parsed.has("help") {
        return print(io, &help(verb));
    }
    // On a terminal, a verb's records are drawn as tables: the verb writes
    // JSON Lines as always, into a buffer the tables are drawn from.
    let tables = io.stdout_tty && !parsed.has("json") && verb.output == Some("records") && verb.name != "table";
    let mut buf = Vec::new();
    let code = {
        let mut ctx = Ctx {
            stdin: &mut *io.stdin,
            stdout: if tables { &mut buf } else { &mut *io.stdout },
            diag: Diag::new(&mut *io.stderr),
            stdin_tty: io.stdin_tty,
            stdout_tty: io.stdout_tty,
            style: io.style,
        };
        (verb.run)(&parsed, &mut ctx)
    };
    if !tables {
        return code;
    }
    let mut t = crate::table::Tables::new(verb.name == "merge");
    for line in buf.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
        t.line(line).expect("nessie's own records are JSON objects");
    }
    match io.stdout.write_all(t.render(io.style).as_bytes()) {
        Ok(()) => code,
        Err(_) => code.max(exit::PROBLEMS),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verb(flags: &'static [Flag]) -> Verb {
        Verb {
            name: "t",
            summary: "s",
            usage: "u",
            input: None,
            output: None,
            roles: &[],
            flags,
            notes: "",
            run: |_, _| 0,
        }
    }

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_gnu_style_flags_anywhere() {
        static F: [Flag; 2] = [OUTPUT, MIN_SEVERITY];
        let v = verb(&F);
        let a = parse(&v, &args(&["a.nessus", "--min-severity", "2", "--output", "-", "--min-severity=3"])).unwrap();
        assert!(a.has("output"));
        assert_eq!(a.value("min-severity"), Some("3"));
        assert_eq!(a.positional, args(&["a.nessus", "-"]));
    }

    #[test]
    fn double_dash_ends_flags() {
        let v = verb(&[]);
        let a = parse(&v, &args(&["--", "--json"])).unwrap();
        assert!(!a.has("json"));
        assert_eq!(a.positional, args(&["--json"]));
    }

    #[test]
    fn refuses_unknown_and_malformed_flags() {
        static F: [Flag; 2] = [OUTPUT, MIN_SEVERITY];
        let v = verb(&F);
        assert!(parse(&v, &args(&["--nope"])).is_err());
        assert!(parse(&v, &args(&["-x"])).is_err());
        assert!(parse(&v, &args(&["--output=1"])).is_err());
        assert!(parse(&v, &args(&["--min-severity"])).is_err());
    }
}
