//! Records as tables, for a person at a terminal, in rpt's style: rounded
//! grey borders, the terminal's own colours, severities coloured. Only the
//! Name column is cut to fit the width, with `…`.
//!
//! Tables are only ever drawn from records already written as JSON Lines,
//! so what a pipe gets and what a terminal shows can't drift apart.

use serde_json::Value;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// How to draw: colour or not (NO_COLOR, TERM=dumb), and the terminal's
/// width in columns (0 when unknown: nothing is cut).
#[derive(Clone, Copy, Debug)]
pub struct Style {
    pub color: bool,
    pub width: usize,
}

#[derive(Clone, Copy, PartialEq)]
enum Paint {
    Plain,
    Severity(u8),
    State,
}

struct Cell {
    text: String,
    paint: Paint,
}

fn plain(s: impl Into<String>) -> Cell {
    Cell { text: clean(&s.into()), paint: Paint::Plain }
}

/// One line, control characters (escapes included) shown as spaces.
fn clean(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect()
}

fn sgr(st: Style, code: &str, s: &str) -> String {
    if st.color && !code.is_empty() { format!("\x1b[{code}m{s}\x1b[0m") } else { s.to_string() }
}

const GREY: &str = "90";

fn severity_code(sev: u8) -> &'static str {
    match sev {
        4 => "1;31",
        3 => "1;38;5;208", // 256-colour orange: ANSI has none
        2 => "33",
        1 => "34",
        _ => GREY,
    }
}

fn state_code(state: &str) -> &'static str {
    match state {
        "new" => "31",
        "fixed" => "32",
        "host-missing" => "33",
        _ => "",
    }
}

fn paint(st: Style, cell: &Cell, text: &str) -> String {
    match cell.paint {
        Paint::Plain => text.to_string(),
        Paint::Severity(s) => sgr(st, severity_code(s), text),
        Paint::State => sgr(st, state_code(&cell.text), text),
    }
}

/// Cuts `s` to `w` columns, ending in `…` when anything was cut.
fn cut(s: &str, w: usize) -> String {
    if s.width() <= w {
        return s.to_string();
    }
    let mut out = String::new();
    let mut used = 0;
    for c in s.chars() {
        let cw = c.width().unwrap_or(0);
        if used + cw + 1 > w {
            break;
        }
        used += cw;
        out.push(c);
    }
    out.push('…');
    out
}

/// The narrowest the cut column gets, however narrow the terminal.
const MIN_CUT: usize = 12;

/// Draws one table. `cut_col` is the column cut to fit.
fn draw(headers: &[&str], rows: &[Vec<Cell>], cut_col: Option<usize>, st: Style) -> String {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.width()).collect();
    for row in rows {
        for (i, c) in row.iter().enumerate() {
            widths[i] = widths[i].max(c.text.width());
        }
    }
    let total: usize = widths.iter().map(|w| w + 3).sum::<usize>() + 1;
    if let Some(i) = cut_col
        && st.width > 0
        && total > st.width
    {
        widths[i] = st.width.saturating_sub(total - widths[i]).max(MIN_CUT.min(widths[i]));
    }
    let rule = |l: &str, m: &str, r: &str| {
        let segs: Vec<String> = widths.iter().map(|w| "─".repeat(w + 2)).collect();
        sgr(st, GREY, &format!("{l}{}{r}", segs.join(m))) + "\n"
    };
    let bar = sgr(st, GREY, "│");
    let line = |cells: Vec<String>| {
        let mut s = bar.clone();
        for c in cells {
            s.push(' ');
            s.push_str(&c);
            s.push(' ');
            s.push_str(&bar);
        }
        s + "\n"
    };
    let pad = |text: &str, w: usize| format!("{text}{}", " ".repeat(w.saturating_sub(text.width())));
    let mut out = rule("╭", "┬", "╮");
    out += &line(headers.iter().zip(&widths).map(|(h, w)| sgr(st, "1", &pad(h, *w))).collect());
    out += &rule("├", "┼", "┤");
    for row in rows {
        out += &line(
            row.iter()
                .zip(&widths)
                .map(|(c, w)| {
                    let t = cut(&c.text, *w);
                    let padded = pad(&t, *w);
                    // Colour the text only, never the padding.
                    paint(st, c, &t) + &padded[t.len()..]
                })
                .collect(),
        );
    }
    out + &rule("╰", "┴", "╯")
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or_default()
}

fn n(v: &Value, k: &str) -> u64 {
    v.get(k).and_then(Value::as_u64).unwrap_or_default()
}

/// A Host as one name: fqdn, else ip, else name (the rule `scope` uses).
fn host_label(h: &Value) -> String {
    ["fqdn", "ip", "name"].iter().map(|k| s(h, k)).find(|v| !v.is_empty()).unwrap_or_default().to_string()
}

fn port(v: &Value) -> String {
    match n(v, "port") {
        0 => "-".into(),
        p => format!("{p}/{}", s(v, "protocol")),
    }
}

fn sev_cell(sev: u8) -> Cell {
    Cell { text: sev.to_string(), paint: Paint::Severity(sev) }
}

fn sev(v: &Value) -> u8 {
    n(v, "severity").min(4) as u8
}

/// Severity descending, then Nessus plugin ID, then Host.
fn sort_findings(recs: &mut [&Value]) {
    recs.sort_by(|a, b| {
        sev(b).cmp(&sev(a)).then(n(a, "plugin_id").cmp(&n(b, "plugin_id"))).then_with(|| {
            let h = |v: &Value| v.get("host").map(host_label).unwrap_or_default();
            h(a).cmp(&h(b))
        })
    });
}

fn plural(count: usize, noun: &str) -> String {
    format!("{count} {noun}{}", if count == 1 { "" } else { "s" })
}

/// "14 results · 4 1 · 3 1 · 2 4 · 0 8": a count, then each severity with
/// any, highest first.
fn severity_totals(st: Style, count: usize, noun: &str, sevs: impl Iterator<Item = u8>) -> String {
    let mut by = [0usize; 5];
    for s in sevs {
        by[usize::from(s.min(4))] += 1;
    }
    let mut parts = vec![sgr(st, "2", &plural(count, noun))];
    for s in (0..5u8).rev() {
        if by[usize::from(s)] > 0 {
            parts.push(sgr(st, severity_code(s), &s.to_string()) + &sgr(st, "2", &format!(" {}", by[usize::from(s)])));
        }
    }
    parts.join(&sgr(st, "2", " · ")) + "\n"
}

/// Records collected for drawing, grouped by what table they go in.
pub struct Tables {
    /// merge's results are drawn grouped by Nessus plugin, like items.
    group_results: bool,
    groups: Vec<(&'static str, Vec<Value>)>,
    /// Lines of kinds with no table, shown as they came, after the tables.
    others: Vec<String>,
    /// Upstream `problem` records, for stderr.
    pub problems: Vec<Value>,
}

/// The table a kind goes in; None for kinds with no table.
fn table_of(v: &Value, group_results: bool) -> Option<&'static str> {
    Some(match s(v, "kind") {
        "nessus-result" if v.get("diff").is_some() => "diff",
        "nessus-result" if group_results => "merged",
        "nessus-result" => "results",
        "nessus-item" => "items",
        "nessus-host" => "hosts",
        "nessus-scan" => "scan",
        "nessus-service" => "services",
        "scope" => "scope",
        "command" => "commands",
        "version" => "version",
        _ => return None,
    })
}

impl Tables {
    pub fn new(group_results: bool) -> Self {
        Self { group_results, groups: Vec::new(), others: Vec::new(), problems: Vec::new() }
    }

    /// Adds one line of input. Err when it isn't a JSON object.
    pub fn line(&mut self, raw: &[u8]) -> Result<(), String> {
        let v: Value = serde_json::from_slice(raw).map_err(|e| format!("invalid JSON: {e}"))?;
        if !v.is_object() {
            return Err("not a JSON object".into());
        }
        if s(&v, "kind") == "problem" {
            self.problems.push(v);
            return Ok(());
        }
        match table_of(&v, self.group_results) {
            Some(t) => match self.groups.iter_mut().find(|(k, _)| *k == t) {
                Some((_, list)) => list.push(v),
                None => self.groups.push((t, vec![v])),
            },
            None => self.others.push(clean(&String::from_utf8_lossy(raw))),
        }
        Ok(())
    }

    /// The tables, in the order each kind first appeared, then the others.
    pub fn render(&self, st: Style) -> String {
        let mut out = String::new();
        for (t, recs) in &self.groups {
            if !out.is_empty() {
                out.push('\n');
            }
            out += &match *t {
                "results" => results(recs, st),
                "merged" => merged(recs, st),
                "items" => items(recs, st),
                "hosts" => hosts(recs, st),
                "scan" => scans(recs, st),
                "diff" => diff(recs, st),
                "services" => services(recs, st),
                "scope" => scope(recs, st),
                "commands" => commands(recs, st),
                "version" => versions(recs),
                _ => unreachable!(),
            };
        }
        for l in &self.others {
            out += l;
            out.push('\n');
        }
        out
    }
}

/// A problem record as one line of text for stderr.
pub fn problem_text(p: &Value) -> String {
    let mut loc = s(p, "path").to_string();
    if let Some(l) = p.get("line").and_then(Value::as_u64) {
        loc += &format!(":{l}");
        if let Some(c) = p.get("column").and_then(Value::as_u64) {
            loc += &format!(":{c}");
        }
    }
    let rule = s(p, "rule");
    let level = match s(p, "level") {
        "" => "error".to_string(),
        l => l.to_string(),
    };
    let rule = if rule.is_empty() { String::new() } else { format!("[{rule}]") };
    clean(&format!("{loc}: {level}{rule}: {}", s(p, "message")))
}

fn results(recs: &[Value], st: Style) -> String {
    let mut sorted: Vec<&Value> = recs.iter().collect();
    sort_findings(&mut sorted);
    let rows: Vec<Vec<Cell>> = sorted
        .iter()
        .map(|r| {
            vec![
                plain(host_label(&r["host"])),
                plain(port(r)),
                sev_cell(sev(r)),
                plain(n(r, "plugin_id").to_string()),
                plain(s(r, "plugin_name")),
            ]
        })
        .collect();
    draw(&["Host", "Port", "Sev", "Plugin", "Name"], &rows, Some(4), st)
        + &severity_totals(st, recs.len(), "result", recs.iter().map(sev))
}

/// One row of the items table, from an Item or from merge's Results.
struct ItemRow {
    severity: u8,
    plugin_id: u64,
    name: String,
    hosts: usize,
    endpoints: usize,
}

fn item_table(mut rows: Vec<ItemRow>, st: Style, footer: String) -> String {
    rows.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.plugin_id.cmp(&b.plugin_id)));
    let cells: Vec<Vec<Cell>> = rows
        .iter()
        .map(|r| {
            vec![
                sev_cell(r.severity),
                plain(r.plugin_id.to_string()),
                plain(&r.name),
                plain(r.hosts.to_string()),
                plain(r.endpoints.to_string()),
            ]
        })
        .collect();
    draw(&["Sev", "Plugin", "Name", "Hosts", "Endpoints"], &cells, Some(2), st) + &footer
}

fn items(recs: &[Value], st: Style) -> String {
    // Parts of one Item are one row.
    let mut rows: Vec<ItemRow> = Vec::new();
    for r in recs {
        let hosts = r["hosts"].as_array().map(Vec::as_slice).unwrap_or_default();
        let endpoints = hosts.iter().map(|h| h["endpoints"].as_array().map_or(0, Vec::len)).sum();
        match rows.iter_mut().find(|x| x.plugin_id == n(r, "plugin_id")) {
            Some(x) => {
                x.hosts += hosts.len();
                x.endpoints += endpoints;
            }
            None => rows.push(ItemRow {
                severity: sev(r),
                plugin_id: n(r, "plugin_id"),
                name: s(r, "plugin_name").into(),
                hosts: hosts.len(),
                endpoints,
            }),
        }
    }
    let footer = severity_totals(st, rows.len(), "item", rows.iter().map(|r| r.severity));
    item_table(rows, st, footer)
}

fn merged(recs: &[Value], st: Style) -> String {
    let mut rows: Vec<(ItemRow, Vec<String>)> = Vec::new();
    for r in recs {
        let h = host_label(&r["host"]);
        match rows.iter_mut().find(|(x, _)| x.plugin_id == n(r, "plugin_id")) {
            Some((x, hosts)) => {
                x.severity = x.severity.max(sev(r));
                x.endpoints += 1;
                if !hosts.contains(&h) {
                    hosts.push(h);
                }
            }
            None => rows.push((
                ItemRow {
                    severity: sev(r),
                    plugin_id: n(r, "plugin_id"),
                    name: s(r, "plugin_name").into(),
                    hosts: 0,
                    endpoints: 1,
                },
                vec![h],
            )),
        }
    }
    let rows: Vec<ItemRow> = rows
        .into_iter()
        .map(|(mut x, h)| {
            x.hosts = h.len();
            x
        })
        .collect();
    let footer = severity_totals(st, recs.len(), "result", recs.iter().map(sev));
    item_table(rows, st, footer)
}

fn hosts(recs: &[Value], st: Style) -> String {
    let rows: Vec<Vec<Cell>> = recs
        .iter()
        .map(|r| {
            let h = &r["host"];
            let os = s(&r["properties"], "operating-system").lines().next().unwrap_or_default();
            vec![
                plain(host_label(h)),
                plain(s(h, "ip")),
                plain(s(h, "fqdn")),
                plain(os),
                plain(n(&r["results"], "total").to_string()),
            ]
        })
        .collect();
    draw(&["Host", "IP", "FQDN", "OS", "Results"], &rows, Some(3), st)
        + &sgr(st, "2", &plural(recs.len(), "host"))
        + "\n"
}

fn scans(recs: &[Value], st: Style) -> String {
    let mut out = String::new();
    for (i, r) in recs.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let file = s(&r["scan"], "file");
        let title = match s(r, "name") {
            "" => file,
            name => name,
        };
        out += &sgr(st, "1", &clean(title));
        out.push('\n');
        let hosts = n(r, "hosts").to_string();
        for (k, v) in [
            ("File", file),
            ("Policy", s(r, "policy_name")),
            ("Nessus version", s(r, "nessus_version")),
            ("Feed", s(r, "feed_version")),
            ("Hosts", hosts.as_str()),
        ] {
            if !v.is_empty() {
                out += &format!("  {}  {}\n", sgr(st, "2", &format!("{k:<14}")), clean(v));
            }
        }
        let c = &r["results"];
        let sevs = (0..5u8).flat_map(|sv| std::iter::repeat_n(sv, n(c, &sv.to_string()) as usize));
        out += "  ";
        out += &severity_totals(st, n(c, "total") as usize, "result", sevs);
    }
    out
}

fn diff(recs: &[Value], st: Style) -> String {
    let mut sorted: Vec<&Value> = recs.iter().collect();
    sort_findings(&mut sorted);
    let rows: Vec<Vec<Cell>> = sorted
        .iter()
        .map(|r| {
            let d = &r["diff"];
            let changed: Vec<&str> =
                d["changed"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
            vec![
                Cell { text: clean(s(d, "state")), paint: Paint::State },
                plain(host_label(&r["host"])),
                plain(port(r)),
                sev_cell(sev(r)),
                plain(n(r, "plugin_id").to_string()),
                plain(s(r, "plugin_name")),
                plain(changed.join(", ")),
            ]
        })
        .collect();
    let mut parts = vec![sgr(st, "2", &plural(recs.len(), "result"))];
    for state in ["new", "fixed", "host-missing", "present"] {
        let count = recs.iter().filter(|r| s(&r["diff"], "state") == state).count();
        if count > 0 {
            parts.push(sgr(st, state_code(state), state) + &sgr(st, "2", &format!(" {count}")));
        }
        if state == "present" {
            let ch = recs.iter().filter(|r| r["diff"]["changed"].as_array().is_some_and(|a| !a.is_empty())).count();
            if ch > 0 {
                parts.push(sgr(st, "2", &format!("changed {ch}")));
            }
        }
    }
    draw(&["State", "Host", "Port", "Sev", "Plugin", "Name", "Changed"], &rows, Some(5), st)
        + &parts.join(&sgr(st, "2", " · "))
        + "\n"
}

fn services(recs: &[Value], st: Style) -> String {
    let rows: Vec<Vec<Cell>> = recs
        .iter()
        .map(|r| {
            let ids: Vec<String> =
                r["plugin_ids"].as_array().map(|a| a.iter().map(|v| v.to_string()).collect()).unwrap_or_default();
            vec![plain(host_label(&r["host"])), plain(port(r)), plain(s(r, "svc_name")), plain(ids.join(", "))]
        })
        .collect();
    draw(&["Host", "Port", "Service", "Plugins"], &rows, Some(3), st)
        + &sgr(st, "2", &plural(recs.len(), "service"))
        + "\n"
}

fn scope(recs: &[Value], st: Style) -> String {
    let rows: Vec<Vec<Cell>> = recs.iter().map(|r| vec![plain(s(r, "host"))]).collect();
    draw(&["Host"], &rows, None, st)
}

fn commands(recs: &[Value], st: Style) -> String {
    let rows: Vec<Vec<Cell>> =
        recs.iter().map(|r| vec![plain(s(r, "name")), plain(s(r, "source")), plain(s(r, "summary"))]).collect();
    draw(&["Verb", "Source", "Summary"], &rows, Some(2), st)
}

fn versions(recs: &[Value]) -> String {
    recs.iter().map(|r| clean(&format!("{} {}", s(r, "name"), s(r, "version"))) + "\n").collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const PLAIN: Style = Style { color: false, width: 0 };

    #[test]
    fn cuts_only_the_name_column_with_an_ellipsis() {
        let mut t = Tables::new(false);
        let r = json!({"kind":"nessus-result","host":{"name":"h"},"port":443,"protocol":"tcp","severity":2,
            "plugin_id":1,"plugin_name":"A very long plugin name that will not fit at all"});
        t.line(r.to_string().as_bytes()).unwrap();
        let out = t.render(Style { color: false, width: 50 });
        for l in out.lines().take(5) {
            assert!(l.width() <= 50, "{l}");
        }
        assert!(out.contains("443/tcp") && out.contains('…'), "{out}");
    }

    #[test]
    fn sorts_by_severity_then_plugin_then_host() {
        let mut t = Tables::new(false);
        for (h, sv, id) in [("b", 1, 5), ("a", 4, 9), ("c", 4, 2), ("a", 1, 5)] {
            let r = json!({"kind":"nessus-result","host":{"name":h},"port":0,"protocol":"tcp","severity":sv,"plugin_id":id,"plugin_name":"n"});
            t.line(r.to_string().as_bytes()).unwrap();
        }
        let out = t.render(PLAIN);
        let order: Vec<&str> = out.lines().skip(3).take(4).map(|l| l.split('│').nth(1).unwrap().trim()).collect();
        assert_eq!(order, ["c", "a", "a", "b"]);
    }

    #[test]
    fn colour_never_reaches_plain_output_and_escapes_are_cleaned() {
        let mut t = Tables::new(false);
        let r = json!({"kind":"nessus-result","host":{"name":"\u{1b}[31mx"},"port":0,"protocol":"tcp","severity":4,"plugin_id":1,"plugin_name":"n"});
        t.line(r.to_string().as_bytes()).unwrap();
        assert!(!t.render(PLAIN).contains('\x1b'));
        assert!(t.render(Style { color: true, width: 0 }).contains("\x1b[1;31m4\x1b[0m"));
    }

    #[test]
    fn problems_are_kept_apart_and_unknown_kinds_follow_as_json() {
        let mut t = Tables::new(false);
        t.line(br#"{"kind":"problem","path":"-","line":3,"rule":"readable","level":"error","message":"bad"}"#).unwrap();
        t.line(br#"{"kind":"finding","id":"F-1"}"#).unwrap();
        assert!(t.line(b"nope").is_err());
        assert_eq!(problem_text(&t.problems[0]), "-:3: error[readable]: bad");
        assert_eq!(t.render(PLAIN), "{\"kind\":\"finding\",\"id\":\"F-1\"}\n");
    }
}
