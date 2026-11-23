//! Extensions: `nessie-<name>` programs on PATH, run as `nessie <name>`,
//! following rpt's plugin protocol.
//!
//! An extension gets nessie's arguments, stdin, stdout and stderr, and
//! `NESSIE_BIN`, the absolute path of the nessie that started it. On a
//! terminal, one whose `--describe` says `"output":"records"` has its
//! stdout drawn as tables, as the built-ins' is.

use crate::table::{Style, Tables};
use serde_json::{Map, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

/// An extension's name: what follows `nessie-`.
pub fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// PATH's directories, skipping empty and relative entries (as rpt does:
/// a relative entry would run whatever the current folder holds).
fn dirs() -> Vec<PathBuf> {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).filter(|d| d.is_absolute()).collect())
        .unwrap_or_default()
}

fn executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    // metadata follows symlinks.
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// The first `nessie-<name>` in PATH order.
pub fn lookup(name: &str) -> Option<PathBuf> {
    if !valid_name(name) {
        return None;
    }
    dirs().into_iter().map(|d| d.join(format!("nessie-{name}"))).find(|p| executable(p))
}

/// Every extension on PATH, the first of each name, sorted by name.
pub fn discover() -> Vec<(String, PathBuf)> {
    let mut out: Vec<(String, PathBuf)> = Vec::new();
    for d in dirs() {
        let Ok(entries) = std::fs::read_dir(&d) else { continue };
        let mut found: Vec<(String, PathBuf)> = entries
            .filter_map(Result::ok)
            .filter_map(|e| {
                let file = e.file_name().into_string().ok()?;
                let name = file.strip_prefix("nessie-")?.to_string();
                let p = d.join(&file);
                (valid_name(&name) && executable(&p)).then_some((name, p))
            })
            .collect();
        found.retain(|(n, _)| !out.iter().any(|(m, _)| m == n));
        out.extend(found);
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// This nessie's absolute path, for `NESSIE_BIN`.
pub fn self_path() -> String {
    std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "nessie".into())
}

fn command(path: &Path, args: &[String]) -> Command {
    let mut c = Command::new(path);
    c.args(args).env("NESSIE_BIN", self_path());
    c
}

/// How long an extension gets to answer `--describe`.
const DESCRIBE_TIMEOUT: Duration = Duration::from_secs(2);

/// An extension's `--describe` answer.
pub fn describe(path: &Path) -> Result<Map<String, Value>, String> {
    let mut child = command(path, &["--describe".into()])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("can't run: {e}"))?;
    let mut out = child.stdout.take().expect("piped");
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = out.by_ref().take(1 << 20).read_to_end(&mut buf);
        buf
    });
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().map_err(|e| e.to_string())? {
            break s;
        }
        if start.elapsed() > DESCRIBE_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("--describe took over {} s", DESCRIBE_TIMEOUT.as_secs()));
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let buf = reader.join().unwrap_or_default();
    if !status.success() {
        return Err(format!("--describe failed ({status})"));
    }
    let line = buf.split(|b| *b == b'\n').find(|l| !l.iter().all(u8::is_ascii_whitespace)).unwrap_or_default();
    match serde_json::from_slice(line) {
        Ok(Value::Object(m)) => Ok(m),
        _ => Err("--describe didn't print a JSON object".into()),
    }
}

/// The child being waited for, for the signal handler.
static CHILD: AtomicI32 = AtomicI32::new(0);

extern "C" fn relay(sig: libc::c_int) {
    let pid = CHILD.load(Ordering::SeqCst);
    if pid > 0 {
        // SAFETY: kill is async-signal-safe.
        unsafe { libc::kill(pid, sig) };
    }
}

/// While alive: SIGINT is ignored (the terminal sends it to the child too,
/// as they share a process group) and SIGTERM and SIGHUP are passed on.
struct Relay {
    old: [(libc::c_int, libc::sighandler_t); 3],
}

impl Relay {
    fn new(pid: u32) -> Self {
        CHILD.store(pid as i32, Ordering::SeqCst);
        let handler = relay as extern "C" fn(libc::c_int) as libc::sighandler_t;
        // SAFETY: installing handlers; restored on drop.
        let old = unsafe {
            [
                (libc::SIGINT, libc::signal(libc::SIGINT, libc::SIG_IGN)),
                (libc::SIGTERM, libc::signal(libc::SIGTERM, handler)),
                (libc::SIGHUP, libc::signal(libc::SIGHUP, handler)),
            ]
        };
        Self { old }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        for (sig, h) in self.old {
            // SAFETY: restoring what was there.
            unsafe { libc::signal(sig, h) };
        }
        CHILD.store(0, Ordering::SeqCst);
    }
}

/// An exit code as a shell gives it: 128 and the number for a signal.
fn code(s: ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    s.code().unwrap_or_else(|| 128 + s.signal().unwrap_or(0))
}

/// Arguments that are never wrapped: they ask for something other than
/// records.
fn unwrapped(args: &[String]) -> bool {
    args.iter().take_while(|a| *a != "--").any(|a| matches!(a.as_str(), "--json" | "--help" | "-h" | "--describe"))
        || args.first().is_some_and(|a| a.starts_with("__complete"))
}

/// Runs an extension. stdin and stderr are the process's own; stdout is
/// too, unless the extension's records are drawn as tables.
pub fn run(
    path: &Path,
    args: &[String],
    stdout: &mut dyn Write,
    stdout_tty: bool,
    style: Style,
    stderr: &mut dyn Write,
) -> i32 {
    let wrap = stdout_tty
        && !unwrapped(args)
        && describe(path).is_ok_and(|d| d.get("output").and_then(Value::as_str) == Some("records"));
    let _ = stdout.flush();
    let mut cmd = command(path, args);
    if wrap {
        cmd.stdout(Stdio::piped());
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(stderr, "nessie: {}: can't run: {e}", path.display());
            return crate::exit::PROBLEMS;
        }
    };
    let relay = Relay::new(child.id());
    let mut bad = false;
    if let Some(out) = child.stdout.take() {
        bad = draw(out, stdout, style, stderr);
    }
    let status = child.wait();
    drop(relay);
    match status {
        Ok(s) if bad => code(s).max(crate::exit::PROBLEMS),
        Ok(s) => code(s),
        Err(e) => {
            let _ = writeln!(stderr, "nessie: {}: {e}", path.display());
            crate::exit::PROBLEMS
        }
    }
}

/// Draws an extension's stdout as tables. Output that doesn't start with
/// `{` passes through unchanged; problem records are dropped (they're on
/// the extension's stderr already). True when a line wasn't a record.
fn draw(out: impl Read, stdout: &mut dyn Write, style: Style, stderr: &mut dyn Write) -> bool {
    let mut r = BufReader::new(out);
    let mut first = Vec::new();
    loop {
        first.clear();
        match r.read_until(b'\n', &mut first) {
            Ok(0) => return false,
            Ok(_) if first.iter().all(u8::is_ascii_whitespace) => {
                let _ = stdout.write_all(&first);
            }
            Ok(_) => break,
            Err(_) => return false,
        }
    }
    if first.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
        let _ = stdout.write_all(&first);
        let _ = std::io::copy(&mut r, &mut WriteAdapter(stdout));
        return false;
    }
    let mut t = Tables::new(false);
    let mut bad = false;
    let mut n = 0u64;
    let mut line = first;
    loop {
        n += 1;
        let trimmed = line.strip_suffix(b"\n").unwrap_or(&line);
        let trimmed = trimmed.strip_suffix(b"\r").unwrap_or(trimmed);
        if !trimmed.iter().all(u8::is_ascii_whitespace)
            && let Err(e) = t.line(trimmed)
        {
            bad = true;
            let _ = writeln!(stderr, "nessie: -:{n}: {e}");
        }
        t.problems.clear();
        line = Vec::new();
        match r.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
    let _ = stdout.write_all(t.render(style).as_bytes());
    bad
}

struct WriteAdapter<'a>(&'a mut dyn Write);

impl Write for WriteAdapter<'_> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.write(b)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert!(valid_name("services") && valid_name("x2-y"));
        assert!(!valid_name("") && !valid_name("-x") && !valid_name("A") && !valid_name("a/b"));
    }

    #[test]
    fn what_is_never_wrapped() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(unwrapped(&a(&["x", "--json"])));
        assert!(unwrapped(&a(&["-h"])));
        assert!(unwrapped(&a(&["__complete", ""])));
        assert!(!unwrapped(&a(&["--", "--json"])));
        assert!(!unwrapped(&a(&["scan.nessus"])));
    }

    #[test]
    fn plain_output_passes_through_and_records_are_drawn() {
        let st = Style { color: false, width: 0 };
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert!(!draw(&b"usage: x\n{not json\n"[..], &mut out, st, &mut err));
        assert_eq!(out, b"usage: x\n{not json\n");
        out.clear();
        let recs =
            b"{\"kind\":\"scope\",\"id\":\"1\",\"host\":\"h\"}\n{\"kind\":\"problem\",\"message\":\"m\"}\nbroken\n";
        assert!(draw(&recs[..], &mut out, st, &mut err));
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("│ h    │") && !out.contains("problem"), "{out}");
        assert!(String::from_utf8(err).unwrap().starts_with("nessie: -:3: invalid JSON"));
    }
}
