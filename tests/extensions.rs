//! Extensions, through the real binary: PATH order, shadowing, pass-through,
//! NESSIE_BIN, help, completion, signals, and tables on a pty.

use std::io::Read;
use std::os::fd::{FromRawFd, OwnedFd};
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_nessie");

fn ext_dir(d: &str) -> String {
    format!("{}/testdata/ext/{d}", env!("CARGO_MANIFEST_DIR"))
}

/// PATH with the test extension folders first (in this order), then /bin
/// and /usr/bin for sh, sleep and cat.
fn path(dirs: &[&str]) -> String {
    let mut p: Vec<String> = dirs.iter().map(|d| ext_dir(d)).collect();
    p.extend(["/usr/bin".into(), "/bin".into()]);
    p.join(":")
}

fn nessie(dirs: &[&str], args: &[&str]) -> Command {
    let mut c = Command::new(BIN);
    c.args(args).env("PATH", path(dirs)).env("NO_COLOR", "1").env_remove("ECHO_EXIT").env_remove("ECHO_STDIN");
    c
}

fn out(o: &Output) -> (i32, String, String) {
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stdout).into(),
        String::from_utf8_lossy(&o.stderr).into(),
    )
}

#[test]
fn runs_the_first_on_path_with_arguments_and_nessie_bin() {
    let (code, stdout, stderr) = out(&nessie(&["a", "b"], &["echo", "x", "--flag", "-"]).output().unwrap());
    assert_eq!(code, 0);
    assert!(stdout.starts_with("{\"kind\":\"scope\",\"id\":\"1\",\"host\":\"a x --flag -\"}\n"), "{stdout}");
    let canon = std::fs::canonicalize(BIN).unwrap();
    assert!(stderr.contains(&format!("NESSIE_BIN={}", canon.display())), "{stderr}");
    let (_, stdout, _) = out(&nessie(&["b", "a"], &["echo"]).output().unwrap());
    assert_eq!(stdout, "{\"kind\":\"scope\",\"id\":\"1\",\"host\":\"b\"}\n");
}

#[test]
fn passes_stdin_and_the_exit_code_through() {
    let mut c = nessie(&["a"], &["echo"]);
    c.env("ECHO_STDIN", "1").env("ECHO_EXIT", "3").stdin(Stdio::piped()).stdout(Stdio::piped());
    let mut child = c.spawn().unwrap();
    use std::io::Write;
    child.stdin.take().unwrap().write_all(b"piped in\n").unwrap();
    let (code, stdout, _) = out(&child.wait_with_output().unwrap());
    assert_eq!(code, 3);
    assert!(stdout.ends_with("piped in\n"), "{stdout}");
}

#[test]
fn built_ins_win_and_unknown_verbs_are_usage_errors() {
    let (code, stdout, _) = out(&nessie(&["b"], &["results", "testdata/scans/compliance.nessus"]).output().unwrap());
    assert_eq!(code, 0);
    assert!(stdout.starts_with("{\"kind\":\"nessus-result\""));
    let (code, _, stderr) = out(&nessie(&["a"], &["nope"]).output().unwrap());
    assert_eq!(code, 2);
    assert!(stderr.contains("no nessie-nope on PATH"), "{stderr}");
    // Not executable, or on a relative PATH entry: not found.
    assert_eq!(nessie(&["a"], &["noexec"]).output().unwrap().status.code(), Some(2));
    let rel = Command::new(BIN).arg("echo").env("PATH", "testdata/ext/a:/usr/bin:/bin").output().unwrap();
    assert_eq!(rel.status.code(), Some(2));
}

#[test]
fn help_lists_built_ins_then_extensions() {
    let (code, stdout, stderr) = out(&nessie(&["a", "b"], &["help"]).output().unwrap());
    assert_eq!(code, 0, "{stderr}");
    let recs: Vec<serde_json::Value> = stdout.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    let names: Vec<&str> = recs.iter().map(|r| r["name"].as_str().unwrap()).collect();
    assert_eq!(&names[..3], ["results", "hosts", "scan"]);
    let echo = recs.iter().find(|r| r["name"] == "echo").unwrap();
    assert_eq!(echo["source"], "extension");
    assert_eq!(echo["summary"], "Echo for tests");
    assert_eq!(echo["version"], "9.9.9");
    assert!(echo["path"].as_str().unwrap().ends_with("testdata/ext/a/nessie-echo"));
    let shadow = recs.iter().find(|r| r["name"] == "results" && r["source"] == "extension").unwrap();
    assert_eq!(shadow["shadowed"], true);
    assert!(recs.iter().filter(|r| r["source"] == "builtin").all(|r| r.get("version").is_none()));
    assert_eq!(recs.iter().filter(|r| r["name"] == "echo").count(), 1, "the first on PATH only");
}

#[test]
fn help_warns_about_an_extension_that_wont_describe_itself() {
    let (code, stdout, stderr) = out(&nessie(&["c"], &["help"]).output().unwrap());
    assert_eq!(code, 0);
    assert!(stderr.contains("warning: extension slow: --describe took over 2 s"), "{stderr}");
    assert!(stdout.contains("{\"kind\":\"command\",\"name\":\"slow\",\"source\":\"extension\""), "{stdout}");
}

#[test]
fn help_for_one_verb() {
    let (_, stdout, _) = out(&nessie(&["a"], &["help", "diff"]).output().unwrap());
    assert!(stdout.starts_with("Compare two scans"), "{stdout}");
}

#[test]
fn completes_verbs_flags_files_and_forwards_to_extensions() {
    let (_, stdout, _) = out(&nessie(&["a"], &["__complete", "e"]).output().unwrap());
    assert_eq!(stdout, "echo\textension\n:4\n");
    let (_, stdout, _) = out(&nessie(&["a"], &["__complete", "results", "--o"]).output().unwrap());
    assert_eq!(stdout, "--output\tInclude each Result's plugin_output\n:4\n");
    let (_, stdout, _) = out(&nessie(&["a"], &["__complete", "results", ""]).output().unwrap());
    assert_eq!(stdout, ":0\n");
    let (_, stdout, _) = out(&nessie(&["a"], &["__completeNoDesc", "items", "--min-severity", "h"]).output().unwrap());
    assert_eq!(stdout, "high\n:4\n");
    let (_, stdout, _) = out(&nessie(&["a"], &["__complete", "echo", ""]).output().unwrap());
    assert_eq!(stdout, "from-echo\ta candidate\n:4\n");
}

#[test]
fn passes_sigterm_on_and_exits_like_a_shell() {
    let mut child = nessie(&["a"], &["wait"]).stderr(Stdio::piped()).spawn().unwrap();
    let mut err = child.stderr.take().unwrap();
    let mut buf = [0u8; 6];
    err.read_exact(&mut buf).unwrap(); // "ready\n": the extension is running
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    assert_eq!(child.wait().unwrap().code(), Some(128 + libc::SIGTERM));
}

/// Runs nessie with stdout on a pty 100 columns wide; returns its output.
fn on_pty(dirs: &[&str], args: &[&str]) -> (i32, String) {
    let (mut master, mut slave) = (0, 0);
    let ws = libc::winsize { ws_row: 40, ws_col: 100, ws_xpixel: 0, ws_ypixel: 0 };
    assert_eq!(unsafe { libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null(), &ws) }, 0);
    let (master, slave) = unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
    let mut child = nessie(dirs, args).stdout(Stdio::from(slave)).stderr(Stdio::null()).spawn().unwrap();
    let mut text = Vec::new();
    // Reading the master ends with EIO once the child has closed the slave.
    let _ = std::fs::File::from(master).read_to_end(&mut text);
    let code = child.wait().unwrap().code().unwrap_or(-1);
    (code, String::from_utf8_lossy(&text).replace("\r\n", "\n"))
}

#[test]
fn wraps_record_extensions_on_a_terminal_only() {
    let (code, text) = on_pty(&["a"], &["echo", "x"]);
    assert_eq!(code, 0);
    assert!(text.starts_with("╭"), "{text}");
    assert!(text.contains("│ a x  │"), "{text}");
    assert!(!text.contains("dropped from tables"), "problems aren't drawn: {text}");
    // --json, a describe without output, and plain text all pass through.
    let (_, text) = on_pty(&["a"], &["echo", "--json"]);
    assert!(text.starts_with("{\"kind\":\"scope\""), "{text}");
    let (_, text) = on_pty(&["a"], &["raw"]);
    assert_eq!(text, "{\"kind\":\"scope\",\"id\":\"1\",\"host\":\"raw\"}\n");
    let (_, text) = on_pty(&["a"], &["plain"]);
    assert_eq!(text, "plain text\n");
    // The exit code is still the extension's.
    let mut c = nessie(&["a"], &["echo"]);
    c.env("ECHO_EXIT", "5");
    assert_eq!(c.output().unwrap().status.code(), Some(5));
}

#[test]
fn built_in_tables_on_a_real_terminal() {
    let (code, text) = on_pty(&[], &["help"]);
    assert_eq!(code, 0);
    assert!(text.contains("│ results │ builtin │"), "{text}");
    let (_, text) = on_pty(&[], &["help", "items"]);
    assert!(text.starts_with("Group Results by Nessus plugin"), "{text}");
}
