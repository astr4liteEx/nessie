//! The recursive-descent walk over quick-xml events.

use super::input::Input;
use super::text::{self, Resolved};
use super::{Host, Options, Policy, ReportItem, Visitor};
use crate::diag::{Diag, Loc};
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use std::io::Read;

const ROOT: &str = "NessusClientData_v2";
/// Elements whose single value is a newline-joined list.
const SPLIT: &[&str] = &["cpe", "see_also"];

/// Why reading a file stopped early.
struct Stop(String);

type Res<T> = Result<T, Stop>;

struct Parser<'a, 'd, R: Read> {
    xml: Reader<Input<R>>,
    path: &'a str,
    opts: &'a Options,
    diag: &'a mut Diag<'d>,
    /// Numeric references that became U+FFFD.
    replaced_refs: u64,
    hosts: u64,
    /// Reused for every event, so reading doesn't allocate per event.
    buf: Vec<u8>,
}

/// Parses one scan, calling `v` as it goes. Messages go to `diag`, tagged
/// with `path`. Returns false when the file was refused or broken off.
pub fn parse<R: Read>(src: R, path: &str, opts: &Options, v: &mut dyn Visitor, diag: &mut Diag) -> bool {
    let mut xml = Reader::from_reader(Input::new(src));
    let cfg = xml.config_mut();
    cfg.expand_empty_elements = true;
    cfg.check_end_names = true;
    let mut p = Parser { xml, path, opts, diag, replaced_refs: 0, hosts: 0, buf: Vec::with_capacity(8192) };
    let ok = match p.document(v) {
        Ok(()) => true,
        // An empty message: the visitor asked to stop, which isn't an error.
        Err(Stop(msg)) if msg.is_empty() => true,
        Err(Stop(msg)) => {
            let line = p.xml.get_ref().line();
            p.diag.error(Loc::line(path, line), msg);
            false
        }
    };
    let replaced = p.xml.get_ref().replaced;
    if replaced > 0 {
        p.diag.warning(Loc::path(path), format!("replaced {replaced} invalid UTF-8 sequence(s) with U+FFFD"));
    }
    if p.replaced_refs > 0 {
        let n = p.replaced_refs;
        p.diag.warning(
            Loc::path(path),
            format!("replaced {n} character reference(s) to invalid code points with U+FFFD"),
        );
    }
    ok
}

fn refuse_dtd(ev: &Event) -> Res<()> {
    if let Event::DocType(d) = ev {
        return Err(Stop(if d.contains("<!ENTITY") {
            "refusing an ENTITY declaration (a DTD in a scan is never needed)".into()
        } else {
            "refusing a DOCTYPE (a DTD in a scan is never needed)".into()
        }));
    }
    Ok(())
}

impl<R: Read> Parser<'_, '_, R> {
    /// The next event, owned. DOCTYPE is refused wherever it appears.
    fn next(&mut self) -> Res<Event<'static>> {
        self.buf.clear();
        let ev = self.xml.read_event_into(&mut self.buf).map_err(|e| Stop(format!("broken XML: {e}")))?;
        refuse_dtd(&ev)?;
        Ok(ev.into_owned())
    }

    fn line(&self) -> u64 {
        self.xml.get_ref().line()
    }

    fn error(&mut self, msg: impl std::fmt::Display) {
        let line = self.line();
        self.diag.error(Loc::line(self.path, line), msg);
    }

    /// Skips everything up to the end of the element just started, without
    /// keeping it: quick-xml's read_to_end_into would buffer it all, and the
    /// Policy can be most of a file.
    fn skip(&mut self, _start: &BytesStart) -> Res<()> {
        let mut depth = 0u32;
        loop {
            self.buf.clear();
            let ev = self.xml.read_event_into(&mut self.buf).map_err(|e| Stop(format!("broken XML: {e}")))?;
            refuse_dtd(&ev)?;
            match ev {
                Event::Start(_) => depth += 1,
                Event::End(_) if depth == 0 => return Ok(()),
                Event::End(_) => depth -= 1,
                Event::Eof => return Err(Stop("unexpected end of file".into())),
                _ => {}
            }
        }
    }

    fn document(&mut self, v: &mut dyn Visitor) -> Res<()> {
        loop {
            match self.next()? {
                Event::Start(e) => {
                    let name = e.name();
                    let name = name.as_ref();
                    if name == "NessusClientData" {
                        return Err(Stop(
                            "this is the Nessus v1 format (NessusClientData), which nessie doesn't read: \
                             export the scan as .nessus (v2)"
                                .into(),
                        ));
                    }
                    if name != ROOT {
                        return Err(Stop(format!("not a Nessus scan: the root element is <{name}>, not <{ROOT}>")));
                    }
                    return self.root(v);
                }
                Event::Eof => return Err(Stop("not a Nessus scan: no root element".into())),
                Event::Text(t) if t.xml10_content().trim().is_empty() => {}
                Event::Text(_) | Event::CData(_) | Event::GeneralRef(_) => {
                    return Err(Stop("not a Nessus scan: text before the root element".into()));
                }
                _ => {} // declaration, comments, processing instructions
            }
        }
    }

    fn root(&mut self, v: &mut dyn Visitor) -> Res<()> {
        let mut saw_report = false;
        loop {
            match self.next()? {
                Event::Start(e) => match e.name().as_ref() {
                    "Policy" if self.opts.read_policy => {
                        let p = self.policy()?;
                        v.policy(p);
                    }
                    "Report" => {
                        saw_report = true;
                        let name = self.attr(&e, "name")?;
                        v.report(name.as_deref());
                        self.report(v)?;
                    }
                    _ => self.skip(&e)?,
                },
                Event::End(_) => break,
                Event::Eof => return Err(Stop(format!("unexpected end of file inside <{ROOT}>"))),
                _ => {}
            }
        }
        if !saw_report {
            self.diag.warning(Loc::path(self.path), "empty scan: there is no Report, only a policy");
        } else if self.hosts == 0 {
            self.diag.warning(Loc::path(self.path), "empty scan: the Report has no Hosts");
        }
        // Anything after the root must be whitespace, comments or PIs.
        loop {
            match self.next()? {
                Event::Eof => return Ok(()),
                Event::Text(t) if t.xml10_content().trim().is_empty() => {}
                Event::Comment(_) | Event::PI(_) => {}
                _ => return Err(Stop("content after the root element".into())),
            }
        }
    }

    fn policy(&mut self) -> Res<Policy> {
        let mut p = Policy::default();
        loop {
            match self.next()? {
                Event::Start(e) => match e.name().as_ref() {
                    "policyName" => p.name = Some(self.text()?.trim().to_string()),
                    "Preferences" => {}
                    "ServerPreferences" => p.server_preferences = self.server_preferences()?,
                    _ => self.skip(&e)?,
                },
                Event::End(e) if e.name().as_ref() == "Policy" => return Ok(p),
                Event::End(_) => {}
                Event::Eof => return Err(Stop("unexpected end of file inside <Policy>".into())),
                _ => {}
            }
        }
    }

    fn server_preferences(&mut self) -> Res<Vec<(String, String)>> {
        let mut prefs = Vec::new();
        loop {
            match self.next()? {
                Event::Start(e) if e.name().as_ref() == "preference" => {
                    let (mut name, mut value) = (None, None);
                    loop {
                        match self.next()? {
                            Event::Start(c) => match c.name().as_ref() {
                                "name" => name = Some(self.text()?.trim().to_string()),
                                "value" => value = Some(self.text()?),
                                _ => self.skip(&c)?,
                            },
                            Event::End(_) => break,
                            Event::Eof => return Err(Stop("unexpected end of file inside <preference>".into())),
                            _ => {}
                        }
                    }
                    if let Some(n) = name {
                        prefs.push((n, value.unwrap_or_default()));
                    }
                }
                Event::Start(e) => self.skip(&e)?,
                Event::End(_) => return Ok(prefs),
                Event::Eof => return Err(Stop("unexpected end of file inside <ServerPreferences>".into())),
                _ => {}
            }
        }
    }

    fn report(&mut self, v: &mut dyn Visitor) -> Res<()> {
        loop {
            match self.next()? {
                Event::Start(e) if e.name().as_ref() == "ReportHost" => {
                    self.hosts += 1;
                    let name = self.attr(&e, "name")?.unwrap_or_default();
                    self.host(name, v)?;
                }
                Event::Start(e) => self.skip(&e)?,
                Event::End(_) => return Ok(()),
                Event::Eof => return Err(Stop("unexpected end of file inside <Report>".into())),
                _ => {}
            }
        }
    }

    fn host(&mut self, name: String, v: &mut dyn Visitor) -> Res<()> {
        let mut host = Host { name, properties: Vec::new() };
        let mut announced = false;
        loop {
            match self.next()? {
                Event::Start(e) => match e.name().as_ref() {
                    "HostProperties" => host.properties.extend(self.properties()?),
                    "ReportItem" => {
                        if !announced {
                            announced = true;
                            v.host(&host);
                        }
                        if let Some(item) = self.item(&e)? {
                            v.item(&host, item);
                            if v.stop() {
                                return Err(Stop(String::new()));
                            }
                        }
                    }
                    _ => self.skip(&e)?,
                },
                Event::End(_) => {
                    if !announced {
                        v.host(&host);
                    }
                    v.host_end(&host);
                    return Ok(());
                }
                Event::Eof => return Err(Stop("unexpected end of file inside <ReportHost>".into())),
                _ => {}
            }
        }
    }

    fn properties(&mut self) -> Res<Vec<(String, String)>> {
        let mut props = Vec::new();
        loop {
            match self.next()? {
                Event::Start(e) if e.name().as_ref() == "tag" => {
                    let name = self.attr(&e, "name")?.unwrap_or_default();
                    let value = self.text()?;
                    props.push((name, value));
                }
                Event::Start(e) => self.skip(&e)?,
                Event::End(_) => return Ok(props),
                Event::Eof => return Err(Stop("unexpected end of file inside <HostProperties>".into())),
                _ => {}
            }
        }
    }

    /// Reads a ReportItem. None when it is below --min-severity or its
    /// attributes are invalid (reported, and the file goes on).
    fn item(&mut self, start: &BytesStart) -> Res<Option<ReportItem>> {
        let mut it = ReportItem::default();
        if let Err(msg) = self.item_attrs(start, &mut it) {
            self.error(format!("skipping a Result: {msg}"));
            self.skip(start)?;
            return Ok(None);
        }
        if self.opts.min_severity.is_some_and(|min| it.severity < min) {
            self.skip(start)?;
            return Ok(None);
        }
        loop {
            match self.next()? {
                Event::Start(e) => {
                    let name = e.name().as_ref().to_string();
                    let value = self.text()?;
                    if name == "plugin_output" {
                        if self.opts.output {
                            it.plugin_output = Some(value);
                        }
                        continue;
                    }
                    let values: Vec<String> = if SPLIT.contains(&name.as_str()) {
                        value.split('\n').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect()
                    } else {
                        vec![value.trim().to_string()]
                    };
                    match it.elements.iter_mut().find(|(k, _)| *k == name) {
                        Some((_, list)) => list.extend(values),
                        None => it.elements.push((name, values)),
                    }
                }
                Event::End(_) => return Ok(Some(it)),
                Event::Eof => return Err(Stop("unexpected end of file inside <ReportItem>".into())),
                _ => {}
            }
        }
    }

    fn item_attrs(&mut self, e: &BytesStart, it: &mut ReportItem) -> Result<(), String> {
        let mut seen = [false; 7];
        for a in e.attributes() {
            let a = a.map_err(|e| format!("bad attribute: {e}"))?;
            let value = text::unescape(&a.value, &mut self.replaced_refs)?;
            let key = a.key.as_ref();
            let slot = ["port", "protocol", "svc_name", "severity", "pluginID", "pluginName", "pluginFamily"]
                .iter()
                .position(|k| *k == key);
            let Some(slot) = slot else { continue };
            seen[slot] = true;
            match slot {
                0 => it.port = value.trim().parse().map_err(|_| format!("port {value:?} is not 0-65535"))?,
                1 => it.protocol = value,
                2 => it.svc_name = value,
                3 => {
                    it.severity =
                        value.trim().parse().ok().filter(|s| *s <= 4).ok_or(format!("severity {value:?} is not 0-4"))?
                }
                4 => it.plugin_id = value.trim().parse().map_err(|_| format!("pluginID {value:?} is not a number"))?,
                5 => it.plugin_name = value,
                _ => it.plugin_family = value,
            }
        }
        let names = ["port", "protocol", "svc_name", "severity", "pluginID", "pluginName", "pluginFamily"];
        match seen.iter().position(|s| !s) {
            Some(i) => Err(format!("it has no {} attribute", names[i])),
            None => Ok(()),
        }
    }

    /// An attribute's unescaped value. An unknown entity stops the file.
    fn attr(&mut self, e: &BytesStart, name: &str) -> Res<Option<String>> {
        for a in e.attributes() {
            let a = a.map_err(|err| Stop(format!("broken XML: bad attribute: {err}")))?;
            if a.key.as_ref() == name {
                return text::unescape(&a.value, &mut self.replaced_refs).map(Some).map_err(Stop);
            }
        }
        Ok(None)
    }

    /// The text of the element just started, up to its end: text, CDATA and
    /// references concatenated; nested elements contribute their text.
    fn text(&mut self) -> Res<String> {
        let mut s = String::new();
        let mut depth = 0u32;
        loop {
            match self.next()? {
                Event::Text(t) => s.push_str(&t.xml10_content()),
                Event::CData(c) => s.push_str(&c.into_inner()),
                Event::GeneralRef(r) => match text::resolve(&r) {
                    Resolved::Char(c) => s.push(c),
                    Resolved::Replaced => {
                        self.replaced_refs += 1;
                        s.push('\u{FFFD}');
                    }
                    Resolved::Unknown => {
                        return Err(Stop(format!(
                            "unknown entity &{};: only the five predefined entities and numeric references exist without a DTD",
                            &*r
                        )));
                    }
                },
                Event::Start(_) => depth += 1,
                Event::End(_) if depth == 0 => return Ok(s),
                Event::End(_) => depth -= 1,
                Event::Eof => return Err(Stop("unexpected end of file inside an element".into())),
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Collect {
        report: Option<Option<String>>,
        hosts: Vec<String>,
        items: Vec<(String, ReportItem)>,
        policy: Option<Policy>,
    }

    impl Visitor for Collect {
        fn policy(&mut self, p: Policy) {
            self.policy = Some(p);
        }
        fn report(&mut self, name: Option<&str>) {
            self.report = Some(name.map(String::from));
        }
        fn host(&mut self, h: &Host) {
            self.hosts.push(format!("{}|{}", h.name, h.ip().unwrap_or("-")));
        }
        fn item(&mut self, h: &Host, it: ReportItem) {
            self.items.push((h.name.clone(), it));
        }
    }

    fn run(xml: &str, opts: Options) -> (Collect, bool, String) {
        let mut c = Collect::default();
        let mut err = Vec::new();
        let ok = {
            let mut d = Diag::new(&mut err);
            parse(xml.as_bytes(), "t.nessus", &opts, &mut c, &mut d)
        };
        (c, ok, String::from_utf8(err).unwrap())
    }

    const SCAN: &str = r#"<?xml version="1.0" ?>
<NessusClientData_v2>
<Policy><policyName>P &amp; Q</policyName><Preferences><ServerPreferences>
<preference><name>TARGET</name><value>10.0.0.1</value></preference>
</ServerPreferences><PluginsPreferences><item><pluginName>x</pluginName></item></PluginsPreferences></Preferences></Policy>
<Report name="Scan &amp; Co" xmlns:cm="http://www.nessus.org/cm">
<ReportHost name="web01"><HostProperties><tag name="host-ip">10.0.0.1</tag><tag name="os">linux</tag></HostProperties>
<ReportItem port="443" svc_name="www" protocol="tcp" severity="2" pluginID="57582" pluginName="SSL Self-Signed" pluginFamily="General">
<synopsis> trimmed </synopsis>
<cve>CVE-1</cve><cve>CVE-2</cve>
<see_also>https://a
https://b</see_also>
<plugin_output>
keep &lt;this&gt; &#x1b; <![CDATA[<raw>]]>
</plugin_output>
<cm:compliance-result>PASSED</cm:compliance-result>
</ReportItem>
<ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="19506" pluginName="Scan Info" pluginFamily="Settings"/>
</ReportHost>
</Report>
</NessusClientData_v2>
"#;

    #[test]
    fn reads_hosts_and_results() {
        let (c, ok, err) = run(SCAN, Options { output: true, ..Options::default() });
        assert!(ok, "{err}");
        assert_eq!(err, "");
        assert_eq!(c.report, Some(Some("Scan & Co".into())));
        assert_eq!(c.hosts, vec!["web01|10.0.0.1"]);
        assert!(c.policy.is_none(), "policy is skipped unless asked for");
        assert_eq!(c.items.len(), 2);
        let it = &c.items[0].1;
        assert_eq!((it.port, it.severity, it.plugin_id), (443, 2, 57582));
        let el: Vec<_> = it.elements.iter().map(|(k, v)| format!("{k}={}", v.join(","))).collect();
        assert_eq!(
            el,
            vec!["synopsis=trimmed", "cve=CVE-1,CVE-2", "see_also=https://a,https://b", "cm:compliance-result=PASSED"]
        );
        assert_eq!(it.plugin_output.as_deref(), Some("\nkeep <this> \u{1b} <raw>\n"));
        assert!(c.items[1].1.elements.is_empty());
    }

    #[test]
    fn reads_the_policy_when_asked() {
        let (c, _, _) = run(SCAN, Options { read_policy: true, ..Options::default() });
        let p = c.policy.unwrap();
        assert_eq!(p.name.as_deref(), Some("P & Q"));
        assert_eq!(p.server_preferences, vec![("TARGET".to_string(), "10.0.0.1".to_string())]);
    }

    #[test]
    fn min_severity_drops_results_and_output_is_opt_in() {
        let (c, ok, _) = run(SCAN, Options { min_severity: Some(1), ..Options::default() });
        assert!(ok);
        assert_eq!(c.items.len(), 1);
        assert_eq!(c.items[0].1.plugin_output, None);
    }

    #[test]
    fn refuses_doctype_entity_and_wrong_roots() {
        for (xml, want) in [
            ("<!DOCTYPE x><NessusClientData_v2/>", "refusing a DOCTYPE"),
            ("<!DOCTYPE x [<!ENTITY e \"boom\">]><NessusClientData_v2/>", "refusing an ENTITY"),
            ("<NessusClientData><Report/></NessusClientData>", "Nessus v1 format"),
            ("<html/>", "root element is <html>"),
            ("<NessusClientData_v2><Report>", "unexpected end of file"),
            ("<NessusClientData_v2></Report>", "broken XML"),
        ] {
            let (_, ok, err) = run(xml, Options::default());
            assert!(!ok, "{xml}");
            assert!(err.contains(want), "{xml}: {err}");
        }
    }

    #[test]
    fn an_unknown_entity_stops_the_file() {
        let xml = "<NessusClientData_v2><Report><ReportHost name=\"h\"><HostProperties><tag name=\"a\">&nbsp;</tag></HostProperties></ReportHost></Report></NessusClientData_v2>";
        let (_, ok, err) = run(xml, Options::default());
        assert!(!ok);
        assert!(err.contains("unknown entity &nbsp;"), "{err}");
    }

    #[test]
    fn a_bad_attribute_skips_one_result_and_reading_goes_on() {
        let xml = r#"<NessusClientData_v2><Report><ReportHost name="h">
<ReportItem port="x" svc_name="a" protocol="tcp" severity="0" pluginID="1" pluginName="n" pluginFamily="f"><synopsis>s</synopsis></ReportItem>
<ReportItem port="1" svc_name="a" protocol="tcp" severity="0" pluginID="2" pluginName="n" pluginFamily="f"/>
</ReportHost></Report></NessusClientData_v2>"#;
        let (c, ok, err) = run(xml, Options::default());
        assert!(ok);
        assert!(err.contains("t.nessus:2: skipping a Result: port \"x\""), "{err}");
        assert_eq!(c.items.len(), 1);
    }

    #[test]
    fn warns_on_empty_scans_and_replacements() {
        let (_, ok, err) = run("<NessusClientData_v2><Policy/></NessusClientData_v2>", Options::default());
        assert!(ok);
        assert!(err.contains("warning: empty scan: there is no Report"), "{err}");
        let xml = "<NessusClientData_v2><Report><ReportHost name=\"h\"><HostProperties><tag name=\"a\">x&#xD800;</tag></HostProperties></ReportHost></Report></NessusClientData_v2>";
        let (_, ok, err) = run(xml, Options::default());
        assert!(ok);
        assert!(err.contains("replaced 1 character reference"), "{err}");
    }
}
