//! JSON Lines in and out (convention §1).
//!
//! The reader keeps each line's raw bytes, so a verb can pass a record it
//! doesn't handle through byte for byte. It accepts CRLF, skips blank lines,
//! and caps a line at 16 MiB; a longer line, invalid JSON or JSON that isn't an
//! object is a malformed line, which the caller reports and drops.

use serde_json::{Map, Value};
use std::io::{self, BufRead, Write};

/// The longest line read or written: 16 MiB.
pub const MAX_LINE: usize = 16 * 1024 * 1024;

/// One JSON object, parsed, with the bytes it arrived as.
pub struct Record {
    /// 1-based line number in the stream.
    pub line: u64,
    /// The line as read, without its line end.
    pub raw: Vec<u8>,
    pub obj: Map<String, Value>,
}

impl Record {
    /// The record's `kind` member, if it is a string.
    pub fn kind(&self) -> Option<&str> {
        self.obj.get("kind").and_then(Value::as_str)
    }
}

/// What the reader yields for each non-blank line.
pub enum Item {
    Record(Record),
    /// A line that isn't a JSON object, with why.
    Malformed {
        line: u64,
        reason: String,
    },
}

pub struct Reader<R> {
    r: R,
    line: u64,
    max: usize,
}

impl<R: BufRead> Reader<R> {
    pub fn new(r: R) -> Self {
        Self { r, line: 0, max: MAX_LINE }
    }

    #[cfg(test)]
    fn with_max(r: R, max: usize) -> Self {
        Self { r, line: 0, max }
    }

    /// The next non-blank line, or None at the end of the stream.
    pub fn next_item(&mut self) -> io::Result<Option<Item>> {
        loop {
            let mut buf = Vec::new();
            let (got, too_long) = self.read_line(&mut buf)?;
            if !got {
                return Ok(None);
            }
            self.line += 1;
            if too_long {
                return Ok(Some(Item::Malformed {
                    line: self.line,
                    reason: format!("line longer than {} MiB", self.max / (1024 * 1024)),
                }));
            }
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
            if buf.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            return Ok(Some(match serde_json::from_slice::<Value>(&buf) {
                Ok(Value::Object(obj)) => Item::Record(Record { line: self.line, raw: buf, obj }),
                Ok(_) => Item::Malformed { line: self.line, reason: "not a JSON object".into() },
                Err(e) => Item::Malformed { line: self.line, reason: format!("invalid JSON: {e}") },
            }));
        }
    }

    /// Reads one line into buf without its `\n`, keeping at most `max` bytes
    /// in memory. Returns (a line was read, it was longer than max).
    fn read_line(&mut self, buf: &mut Vec<u8>) -> io::Result<(bool, bool)> {
        let mut got = false;
        let mut too_long = false;
        loop {
            let chunk = self.r.fill_buf()?;
            if chunk.is_empty() {
                return Ok((got, too_long));
            }
            got = true;
            let (take, done) = match memchr(chunk) {
                Some(i) => (i, true),
                None => (chunk.len(), false),
            };
            if !too_long {
                if buf.len() + take > self.max {
                    too_long = true;
                    buf.clear();
                } else {
                    buf.extend_from_slice(&chunk[..take]);
                }
            }
            self.r.consume(if done { take + 1 } else { take });
            if done {
                return Ok((true, too_long));
            }
        }
    }
}

fn memchr(s: &[u8]) -> Option<usize> {
    s.iter().position(|&b| b == b'\n')
}

/// Writes a record as one complete line.
pub fn write_value(w: &mut dyn Write, v: &Value) -> io::Result<()> {
    let mut line = serde_json::to_vec(v).map_err(io::Error::other)?;
    line.push(b'\n');
    w.write_all(&line)
}

/// Writes a line exactly as it was read.
pub fn write_raw(w: &mut dyn Write, raw: &[u8]) -> io::Result<()> {
    let mut line = Vec::with_capacity(raw.len() + 1);
    line.extend_from_slice(raw);
    line.push(b'\n');
    w.write_all(&line)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn items(input: &[u8], max: usize) -> Vec<String> {
        let mut r = Reader::with_max(input, max);
        let mut out = Vec::new();
        while let Some(it) = r.next_item().unwrap() {
            out.push(match it {
                Item::Record(rec) => format!("{}:{}", rec.line, String::from_utf8(rec.raw).unwrap()),
                Item::Malformed { line, reason } => format!("{line}!{reason}"),
            });
        }
        out
    }

    #[test]
    fn reads_records_with_their_line_numbers_and_raw_bytes() {
        let got = items(b"{\"a\":\"\\u00e9\"}\r\n\n  \n[1]\n{\"b\":2}", 100);
        assert_eq!(got, vec!["1:{\"a\":\"\\u00e9\"}", "4!not a JSON object", "5:{\"b\":2}"]);
    }

    #[test]
    fn reports_invalid_json() {
        let got = items(b"{nope\n", 100);
        assert!(got[0].starts_with("1!invalid JSON"), "{got:?}");
    }

    #[test]
    fn a_line_over_the_cap_is_malformed_and_reading_goes_on() {
        let long = format!("{{\"a\":\"{}\"}}\n{{\"b\":1}}\n", "x".repeat(50));
        let got = items(long.as_bytes(), 20);
        assert_eq!(got.len(), 2);
        assert!(got[0].starts_with("1!line longer"), "{got:?}");
        assert_eq!(got[1], "2:{\"b\":1}");
    }
}
