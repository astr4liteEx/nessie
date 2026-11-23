//! Reading `.nessus` (NessusClientData_v2) scans as a stream.
//!
//! `parse` walks one scan and calls a `Visitor` for the policy, the report,
//! each Host and each Result. It holds one ReportItem at a time plus its
//! Host's properties, so memory stays flat however large the scan.

mod input;
mod parse;
mod text;

pub use parse::parse;

/// What `parse` reads and keeps.
#[derive(Clone, Copy, Default)]
pub struct Options {
    /// Keep each Result's plugin_output.
    pub output: bool,
    /// Drop Results below this severity while parsing.
    pub min_severity: Option<u8>,
    /// Read the Policy's name and ServerPreferences; otherwise Policy is skipped.
    pub read_policy: bool,
}

/// The parts of the Policy nessie reads.
#[derive(Debug, Default)]
pub struct Policy {
    pub name: Option<String>,
    /// Every ServerPreferences preference, in file order.
    pub server_preferences: Vec<(String, String)>,
}

/// One ReportHost: its name and every HostProperties tag, in file order.
#[derive(Debug, Default)]
pub struct Host {
    pub name: String,
    pub properties: Vec<(String, String)>,
}

impl Host {
    pub fn property(&self, name: &str) -> Option<&str> {
        self.properties.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    pub fn ip(&self) -> Option<&str> {
        self.property("host-ip").filter(|s| !s.is_empty())
    }

    pub fn fqdn(&self) -> Option<&str> {
        self.property("host-fqdn").filter(|s| !s.is_empty())
    }
}

/// One ReportItem: a Result.
#[derive(Debug, Default, Clone)]
pub struct ReportItem {
    pub port: u16,
    pub protocol: String,
    pub svc_name: String,
    pub severity: u8,
    pub plugin_id: u64,
    pub plugin_name: String,
    pub plugin_family: String,
    /// Every child element but plugin_output, by verbatim name, in first-seen
    /// order: values trimmed, repeats appended, newline-joined cpe and
    /// see_also split.
    pub elements: Vec<(String, Vec<String>)>,
    /// Verbatim, only when Options::output is set and the Result has one.
    pub plugin_output: Option<String>,
}

/// Called as `parse` walks a scan. Every method has an empty default.
/// Nessus's severities by number, as people say them.
pub const SEVERITY_NAMES: [&str; 5] = ["info", "low", "medium", "high", "critical"];

/// A severity's name; numbers above 4 count as critical.
pub fn severity_name(sev: u8) -> &'static str {
    SEVERITY_NAMES[usize::from(sev.min(4))]
}

/// A severity given as 0-4 or as its name (any case).
pub fn parse_severity(s: &str) -> Option<u8> {
    let s = s.trim();
    s.parse::<u8>()
        .ok()
        .filter(|n| *n <= 4)
        .or_else(|| SEVERITY_NAMES.iter().position(|n| n.eq_ignore_ascii_case(s)).map(|i| i as u8))
}

pub trait Visitor {
    /// The Policy, when Options::read_policy is set.
    fn policy(&mut self, _policy: Policy) {}
    /// The Report element, with its name attribute.
    fn report(&mut self, _name: Option<&str>) {}
    /// A Host, once its properties are read and before its Results.
    fn host(&mut self, _host: &Host) {}
    /// A Result on the current Host.
    fn item(&mut self, _host: &Host, _item: ReportItem) {}
    /// A Result on the current Host skipped for being below --min-severity.
    fn below(&mut self, _host: &Host, _severity: u8) {}
    /// The end of a Host.
    fn host_end(&mut self, _host: &Host) {}
    /// Checked after each Result: true stops reading (stdout was closed).
    fn stop(&self) -> bool {
        false
    }
}
