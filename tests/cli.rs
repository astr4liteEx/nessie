mod common;
use common::{lines, run};

#[test]
fn the_tool_describes_itself_on_one_line() {
    let r = run(&["--describe"], b"");
    assert_eq!(r.code, 0);
    assert_eq!(r.stdout.lines().count(), 1);
    let d = &lines(&r.stdout)[0];
    assert_eq!(d["output"], "records");
    assert!(d["summary"].is_string());
}

#[test]
fn every_built_in_describes_itself() {
    for verb in ["results", "hosts", "scan", "items", "merge", "diff", "table", "version"] {
        let r = run(&[verb, "--describe"], b"");
        assert_eq!(r.code, 0, "{verb}");
        let d = &lines(&r.stdout)[0];
        assert_eq!(d["version"], env!("CARGO_PKG_VERSION"), "{verb}");
        assert!(d["usage"].as_str().unwrap().starts_with(&format!("nessie {verb}")), "{verb}");
    }
}

#[test]
fn help_lists_flags_and_exits_zero() {
    let r = run(&["results", "--help"], b"");
    assert_eq!(r.code, 0);
    assert!(r.stdout.contains("--min-severity N"));
    assert!(r.stdout.contains("--json"));
    let r = run(&["--help"], b"");
    assert_eq!(r.code, 0);
    assert!(r.stdout.contains("results"));
}

#[test]
fn version_prints_one_record() {
    let r = run(&["version", "--json"], b"");
    assert_eq!(r.code, 0, "{}", r.stderr);
    let v = &lines(&r.stdout)[0];
    assert_eq!(v["kind"], "version");
    assert_eq!(v["schema_versions"]["nessus-result"], 1);
    assert_eq!(run(&["--version"], b"").stdout, r.stdout);
}

#[test]
fn usage_errors_exit_two() {
    let r = run(&["results", "--nope"], b"");
    assert_eq!(r.code, 2);
    assert!(r.stderr.starts_with("nessie: results: unknown flag --nope"), "{}", r.stderr);
    assert_eq!(run(&[], b"").code, 2);
}
