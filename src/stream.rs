//! Reading Results from either a .nessus scan or a `nessus-result` stream,
//! for the verbs that take both (items, merge, diff).
//!
//! Either way, each Result arrives as a validated `nessus-result` object.
//! Records of other kinds arrive as their raw bytes, to pass through.

use crate::diag::{Diag, Loc};
use crate::inputs::Format;
use crate::jsonl::{self, Item};
use crate::nessus::{self, Host, Options, ReportItem, Visitor};
use crate::records;
use serde_json::{Map, Value};
use std::io::BufRead;

/// A `nessus-result` record, checked to have the members nessie relies on.
#[derive(Clone, Debug)]
pub struct ResultRec {
    pub obj: Map<String, Value>,
}

impl ResultRec {
    /// Checks a parsed object. Err says what is wrong.
    pub fn check(obj: Map<String, Value>) -> Result<Self, String> {
        match obj.get("schema_version").and_then(Value::as_u64) {
            Some(1) => {}
            Some(v) => return Err(format!("nessus-result schema_version {v} is newer than this nessie knows (1)")),
            None => return Err("nessus-result has no schema_version".into()),
        }
        let int = |k: &str, max: u64| obj.get(k).and_then(Value::as_u64).filter(|n| *n <= max).is_some();
        let string = |k: &str| obj.get(k).is_some_and(Value::is_string);
        let object = |k: &str| obj.get(k).is_some_and(Value::is_object);
        let missing = [
            ("plugin_id", int("plugin_id", u64::MAX)),
            ("port", int("port", 65535)),
            ("severity", int("severity", 4)),
            ("protocol", string("protocol")),
            ("svc_name", string("svc_name")),
            ("plugin_name", string("plugin_name")),
            ("plugin_family", string("plugin_family")),
            ("host", object("host")),
            ("scan", object("scan")),
            ("elements", object("elements")),
        ]
        .into_iter()
        .find(|(_, ok)| !ok);
        match missing {
            Some((k, _)) => Err(format!("nessus-result has no valid {k}")),
            None => Ok(Self { obj }),
        }
    }

    pub fn plugin_id(&self) -> u64 {
        self.obj["plugin_id"].as_u64().unwrap_or_default()
    }
    pub fn severity(&self) -> u8 {
        self.obj["severity"].as_u64().unwrap_or_default() as u8
    }
    pub fn port(&self) -> u16 {
        self.obj["port"].as_u64().unwrap_or_default() as u16
    }
    pub fn str(&self, key: &str) -> &str {
        self.obj.get(key).and_then(Value::as_str).unwrap_or_default()
    }
    pub fn host(&self) -> &Value {
        &self.obj["host"]
    }
    pub fn scan(&self) -> &Value {
        &self.obj["scan"]
    }
    pub fn elements(&self) -> &Map<String, Value> {
        self.obj["elements"].as_object().expect("checked")
    }
    pub fn output(&self) -> Option<&str> {
        self.obj.get("plugin_output").and_then(Value::as_str)
    }
}

/// What reading an input yields.
pub enum Ev {
    /// A Host in an XML input, before its Results (diff uses it to tell
    /// a Host that was scanned from one that wasn't).
    #[allow(dead_code)] // read by diff
    Host(Value),
    Result(ResultRec),
    /// A line of another kind, exactly as read.
    Pass(Vec<u8>),
}

/// Reads one input already sniffed as `format`, calling `on` for each event;
/// `on` returns false to stop. Returns false when the input was broken off.
pub fn read(
    name: &str,
    src: &mut dyn BufRead,
    format: Format,
    opts: &Options,
    diag: &mut Diag,
    on: &mut dyn FnMut(Ev) -> bool,
) -> bool {
    match format {
        Format::Xml => {
            let mut v = XmlVisitor {
                file: name.to_string(),
                scan: records::scan(name, None),
                host: Value::Null,
                on,
                stopped: false,
            };
            nessus::parse(src, name, opts, &mut v, diag)
        }
        Format::Jsonl => read_jsonl(name, src, opts, diag, on),
        Format::Empty => true,
        Format::Other(_) => {
            diag.error(Loc::path(name), "neither a .nessus scan nor JSON Lines");
            false
        }
    }
}

struct XmlVisitor<'a> {
    file: String,
    scan: Value,
    host: Value,
    on: &'a mut dyn FnMut(Ev) -> bool,
    stopped: bool,
}

impl Visitor for XmlVisitor<'_> {
    fn report(&mut self, name: Option<&str>) {
        self.scan = records::scan(&self.file, name);
    }

    fn host(&mut self, h: &Host) {
        self.host = records::host(h);
        if !(self.on)(Ev::Host(self.host.clone())) {
            self.stopped = true;
        }
    }

    fn item(&mut self, _: &Host, it: ReportItem) {
        let Value::Object(obj) = records::result(&self.scan, &self.host, it) else { unreachable!() };
        if !(self.on)(Ev::Result(ResultRec { obj })) {
            self.stopped = true;
        }
    }

    fn stop(&self) -> bool {
        self.stopped
    }
}

fn read_jsonl(
    name: &str,
    src: &mut dyn BufRead,
    opts: &Options,
    diag: &mut Diag,
    on: &mut dyn FnMut(Ev) -> bool,
) -> bool {
    let mut r = jsonl::Reader::new(src);
    loop {
        let item = match r.next_item() {
            Ok(Some(i)) => i,
            Ok(None) => return true,
            Err(e) => {
                diag.error(Loc::path(name), format!("can't read: {e}"));
                return false;
            }
        };
        let ev = match item {
            Item::Malformed { line, reason } => {
                diag.error(Loc::line(name, line), reason);
                continue;
            }
            Item::Record(rec) if rec.kind() == Some("nessus-result") => {
                let line = rec.line;
                match ResultRec::check(rec.obj) {
                    Ok(mut res) => {
                        if opts.min_severity.is_some_and(|min| res.severity() < min) {
                            continue;
                        }
                        if !opts.output {
                            res.obj.shift_remove("plugin_output");
                        }
                        Ev::Result(res)
                    }
                    Err(e) => {
                        diag.error(Loc::line(name, line), format!("dropping a record: {e}"));
                        continue;
                    }
                }
            }
            Item::Record(rec) => Ev::Pass(rec.raw),
        };
        if !on(ev) {
            return true;
        }
    }
}
