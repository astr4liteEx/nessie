//! The byte stream the XML parser reads: invalid UTF-8 replaced with U+FFFD,
//! and lines counted so messages can say where they are.
//!
//! quick-xml refuses invalid UTF-8 outright, but a scan with a stray byte in a
//! banner should still convert (lenient about content, strict about structure).

use std::io::{self, BufRead, Read};

const CHUNK: usize = 64 * 1024;
const REPLACEMENT: &[u8] = "\u{FFFD}".as_bytes();

pub struct Input<R> {
    inner: R,
    buf: Vec<u8>,
    pos: usize,
    /// Bytes of an incomplete UTF-8 sequence left over from the last chunk.
    carry: Vec<u8>,
    eof: bool,
    /// Newlines consumed so far.
    lines: u64,
    /// How many invalid sequences were replaced.
    pub replaced: u64,
}

impl<R: Read> Input<R> {
    pub fn new(inner: R) -> Self {
        Self { inner, buf: Vec::new(), pos: 0, carry: Vec::new(), eof: false, lines: 0, replaced: 0 }
    }

    /// The 1-based line the parser has reached.
    pub fn line(&self) -> u64 {
        self.lines + 1
    }

    fn refill(&mut self) -> io::Result<()> {
        self.buf.clear();
        self.pos = 0;
        while self.buf.is_empty() && !self.eof {
            let mut raw = std::mem::take(&mut self.carry);
            let start = raw.len();
            raw.resize(start + CHUNK, 0);
            let n = loop {
                match self.inner.read(&mut raw[start..]) {
                    Ok(n) => break n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            };
            raw.truncate(start + n);
            if n == 0 {
                self.eof = true;
            }
            self.push_valid(&raw);
        }
        Ok(())
    }

    /// Appends `raw` to the buffer with invalid sequences replaced, keeping an
    /// incomplete sequence at the end for the next chunk (unless at EOF).
    fn push_valid(&mut self, mut raw: &[u8]) {
        loop {
            match std::str::from_utf8(raw) {
                Ok(_) => {
                    self.buf.extend_from_slice(raw);
                    return;
                }
                Err(e) => {
                    let ok = e.valid_up_to();
                    self.buf.extend_from_slice(&raw[..ok]);
                    match e.error_len() {
                        Some(bad) => {
                            self.buf.extend_from_slice(REPLACEMENT);
                            self.replaced += 1;
                            raw = &raw[ok + bad..];
                        }
                        None if self.eof => {
                            self.buf.extend_from_slice(REPLACEMENT);
                            self.replaced += 1;
                            return;
                        }
                        None => {
                            self.carry = raw[ok..].to_vec();
                            return;
                        }
                    }
                }
            }
        }
    }
}

impl<R: Read> Read for Input<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let avail = self.fill_buf()?;
        let n = avail.len().min(out.len());
        out[..n].copy_from_slice(&avail[..n]);
        self.consume(n);
        Ok(n)
    }
}

impl<R: Read> BufRead for Input<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.pos >= self.buf.len() {
            self.refill()?;
        }
        Ok(&self.buf[self.pos..])
    }

    fn consume(&mut self, amt: usize) {
        let end = (self.pos + amt).min(self.buf.len());
        self.lines += self.buf[self.pos..end].iter().filter(|&&b| b == b'\n').count() as u64;
        self.pos = end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn through(bytes: &[u8]) -> (String, u64) {
        let mut i = Input::new(bytes);
        let mut s = String::new();
        i.read_to_string(&mut s).unwrap();
        (s, i.replaced)
    }

    #[test]
    fn passes_valid_utf8_through() {
        assert_eq!(through("café\n".as_bytes()), ("café\n".to_string(), 0));
    }

    #[test]
    fn replaces_invalid_bytes() {
        assert_eq!(through(b"a\xffb\xc3"), ("a\u{FFFD}b\u{FFFD}".to_string(), 2));
    }

    #[test]
    fn keeps_a_sequence_split_across_chunks() {
        let mut data = vec![b'x'; CHUNK - 1];
        data.extend_from_slice("é".as_bytes());
        let (s, n) = through(&data);
        assert_eq!(n, 0);
        assert!(s.ends_with('é'));
    }

    #[test]
    fn counts_consumed_lines() {
        let mut i = Input::new(&b"a\nb\nc"[..]);
        assert_eq!(i.line(), 1);
        let n = i.fill_buf().unwrap().len();
        i.consume(n);
        assert_eq!(i.line(), 3);
    }
}
