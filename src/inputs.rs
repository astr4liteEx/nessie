//! Turning a verb's arguments into the inputs it reads: files, or `-` for
//! stdin. With no arguments, stdin is read when it isn't a terminal.

use crate::cli::Ctx;
use std::fs::File;
use std::io::{self, BufRead, BufReader};

/// The inputs named on the command line, checked for usage errors.
pub fn names(positional: &[String], ctx: &Ctx) -> Result<Vec<String>, String> {
    let names: Vec<String> = if positional.is_empty() {
        if ctx.stdin_tty {
            return Err("no input: name a scan, or pipe one in".into());
        }
        vec!["-".into()]
    } else {
        positional.to_vec()
    };
    if names.iter().filter(|n| *n == "-").count() > 1 {
        return Err("stdin can be read once: give - at most once".into());
    }
    Ok(names)
}

/// Opens a named input. Stdin is borrowed from the context.
pub fn open<'a>(name: &str, stdin: &'a mut dyn BufRead) -> io::Result<Box<dyn BufRead + 'a>> {
    if name == "-" { Ok(Box::new(stdin)) } else { Ok(Box::new(BufReader::with_capacity(64 * 1024, File::open(name)?))) }
}

/// What an input holds, judged by its first byte.
#[derive(Debug, PartialEq, Eq)]
pub enum Format {
    Xml,
    Jsonl,
    Empty,
    /// Neither: the first byte, for the message.
    Other(u8),
}

/// Looks at the first non-whitespace byte, consuming a UTF-8 BOM and leading
/// whitespace (both formats ignore them): `<` is XML, `{` is JSON Lines.
pub fn sniff(r: &mut dyn BufRead) -> io::Result<Format> {
    let mut first = true;
    loop {
        let buf = r.fill_buf()?;
        if buf.is_empty() {
            return Ok(Format::Empty);
        }
        if first {
            first = false;
            if buf.starts_with(b"\xEF\xBB\xBF") {
                r.consume(3);
                continue;
            }
        }
        let ws = buf.iter().take_while(|b| b.is_ascii_whitespace()).count();
        if ws == buf.len() {
            r.consume(ws);
            continue;
        }
        let b = buf[ws];
        r.consume(ws);
        return Ok(match b {
            b'<' => Format::Xml,
            b'{' => Format::Jsonl,
            other => Format::Other(other),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffs_the_first_byte() {
        let s = |b: &[u8]| sniff(&mut &b[..]).unwrap();
        assert_eq!(s(b"\xEF\xBB\xBF  \n<?xml"), Format::Xml);
        assert_eq!(s(b"\n{\"kind\":1}"), Format::Jsonl);
        assert_eq!(s(b"  \n "), Format::Empty);
        assert_eq!(s(b"PK\x03\x04"), Format::Other(b'P'));
    }

    #[test]
    fn leaves_the_first_byte_unread() {
        let mut r = &b"  <a/>"[..];
        sniff(&mut r).unwrap();
        assert_eq!(r, b"<a/>");
    }
}
