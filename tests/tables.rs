//! Terminal tables: snapshots at 100 columns without colour, and JSON Lines
//! unchanged off a terminal or with --json.

mod common;
use common::golden::check_as;
use common::{run, run_tty};

const PRO10: &str = "testdata/scans/pro-10.nessus";
const OLD: &str = "testdata/scans/retest-old.nessus";
const NEW: &str = "testdata/scans/retest-new.nessus";

fn cases() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        ("results", vec!["results", PRO10]),
        ("items", vec!["items", PRO10]),
        ("hosts", vec!["hosts", PRO10]),
        ("scan", vec!["scan", PRO10, "testdata/scans/pro-5.nessus"]),
        ("merge", vec!["merge", OLD, NEW]),
        ("diff", vec!["diff", OLD, NEW]),
        ("edge-identity", vec!["results", "testdata/scans/edge-identity.nessus"]),
        ("version", vec!["version"]),
    ]
}

#[test]
fn table_snapshots() {
    for (name, args) in cases() {
        check_as(&format!("table-{name}"), "txt", &run_tty(&args, b"", true));
    }
}

#[test]
fn json_flag_and_pipes_get_the_same_json_lines() {
    for (_, args) in cases() {
        let piped = run(&args, b"");
        let mut with_flag = args.clone();
        with_flag.push("--json");
        let flagged = run_tty(&with_flag, b"", true);
        assert_eq!(piped.stdout, flagged.stdout, "{args:?}");
        assert!(piped.stdout.starts_with('{'), "{args:?}");
    }
}

#[test]
fn table_verb_draws_mixed_kinds_and_sends_problems_to_stderr() {
    let mut input = run(&["scan", PRO10], b"").stdout;
    input.push_str(&run(&["results", "testdata/scans/compliance.nessus"], b"").stdout);
    input.push_str("{\"kind\":\"finding\",\"id\":\"F-1\",\"title\":\"kept as JSON\"}\n");
    input.push_str("{\"kind\":\"problem\",\"path\":\"-\",\"line\":4,\"rule\":\"readable\",\"level\":\"error\",\"message\":\"upstream trouble\"}\n");
    input.push_str("{\"kind\":\"scope\",\"id\":\"s1\",\"host\":\"192.0.2.0/24\"}\n");
    input.push_str("not json\n");
    let r = run_tty(&["table"], input.as_bytes(), true);
    check_as("table-mixed", "txt", &r);
    assert_eq!(r.code, 1, "the malformed line is nessie's error");
    assert!(r.stderr.starts_with("-:4: error[readable]: upstream trouble\n"), "{}", r.stderr);
}

#[test]
fn table_verb_passes_lines_through_off_a_terminal() {
    let input = "{\"kind\":\"finding\",  \"x\":1.0}\nnot even json\n";
    let r = run(&["table"], input.as_bytes());
    assert_eq!((r.code, r.stdout.as_str()), (0, input));
}
