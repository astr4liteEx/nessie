//! Messages on stderr: `nessie: <path>:<line>:<column>: [warning: ]<message>`,
//! leaving out whatever isn't known (convention §3).

use std::io::Write;

/// Where a message points. Every part is optional.
#[derive(Debug, Clone, Copy, Default)]
pub struct Loc<'a> {
    pub path: Option<&'a str>,
    pub line: Option<u64>,
    pub column: Option<u64>,
}

impl<'a> Loc<'a> {
    pub fn none() -> Self {
        Self::default()
    }

    pub fn path(path: &'a str) -> Self {
        Self { path: Some(path), ..Self::default() }
    }

    pub fn line(path: &'a str, line: u64) -> Self {
        Self { path: Some(path), line: Some(line), column: None }
    }
}

/// Writes messages and remembers whether any error was reported, which makes
/// the run exit 1.
pub struct Diag<'w> {
    w: &'w mut dyn Write,
    failed: bool,
}

impl<'w> Diag<'w> {
    pub fn new(w: &'w mut dyn Write) -> Self {
        Self { w, failed: false }
    }

    /// An error: the run will exit 1.
    pub fn error(&mut self, loc: Loc, msg: impl std::fmt::Display) {
        self.failed = true;
        self.emit(loc, "", &msg.to_string());
    }

    /// A warning: printed, but the exit code is unchanged.
    pub fn warning(&mut self, loc: Loc, msg: impl std::fmt::Display) {
        self.emit(loc, "warning: ", &msg.to_string());
    }

    /// True once any error has been reported.
    pub fn failed(&self) -> bool {
        self.failed
    }

    /// The exit code so far: 0, or 1 after an error.
    pub fn code(&self) -> i32 {
        if self.failed { crate::exit::PROBLEMS } else { crate::exit::OK }
    }

    fn emit(&mut self, loc: Loc, level: &str, msg: &str) {
        let mut prefix = String::from("nessie: ");
        if let Some(p) = loc.path {
            prefix.push_str(p);
            prefix.push_str(": ");
            if let Some(l) = loc.line {
                prefix.truncate(prefix.len() - 2);
                prefix.push_str(&format!(":{l}"));
                if let Some(c) = loc.column {
                    prefix.push_str(&format!(":{c}"));
                }
                prefix.push_str(": ");
            }
        }
        // A message must stay on one line.
        let msg = msg.replace('\n', " ");
        let _ = writeln!(self.w, "{prefix}{level}{msg}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(f: impl FnOnce(&mut Diag)) -> (String, bool) {
        let mut buf = Vec::new();
        let failed;
        {
            let mut d = Diag::new(&mut buf);
            f(&mut d);
            failed = d.failed();
        }
        (String::from_utf8(buf).unwrap(), failed)
    }

    #[test]
    fn formats_every_part_it_knows() {
        let (out, failed) = render(|d| {
            d.error(Loc { path: Some("a.nessus"), line: Some(3), column: Some(7) }, "bad");
            d.error(Loc::line("-", 12), "not a JSON object");
            d.warning(Loc::path("x.nessus"), "empty scan");
            d.error(Loc::none(), "two\nlines");
        });
        assert!(failed);
        assert_eq!(
            out,
            "nessie: a.nessus:3:7: bad\nnessie: -:12: not a JSON object\n\
             nessie: x.nessus: warning: empty scan\nnessie: two lines\n"
        );
    }

    #[test]
    fn warnings_alone_do_not_fail() {
        let (_, failed) = render(|d| d.warning(Loc::none(), "w"));
        assert!(!failed);
    }
}
