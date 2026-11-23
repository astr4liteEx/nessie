mod common;
use common::{golden, lines, run, schema};

const SCANS: &str = "testdata/scans";

fn case(name: &str, args: &[&str]) {
    let r = run(args, b"");
    for rec in lines(&r.stdout) {
        schema::validate(&rec);
    }
    golden::check(name, &r);
}

#[test]
fn results_for_every_fixture() {
    for shape in ["pro-10", "pro-5", "vm-export", "compliance", "edge-identity", "empty-report", "policy-only"] {
        let f = format!("{SCANS}/{shape}.nessus");
        case(&format!("results-{shape}"), &["results", &f]);
    }
    case("results-output-pro-10", &["results", "--output", &format!("{SCANS}/pro-10.nessus")]);
    case("results-output-vm-export", &["results", "--output", &format!("{SCANS}/vm-export.nessus")]);
    case("results-min-severity-pro-10", &["results", "--min-severity", "2", &format!("{SCANS}/pro-10.nessus")]);
}

#[test]
fn results_for_every_hostile_case() {
    for shape in [
        "doctype",
        "entity",
        "v1-root",
        "broken",
        "unknown-entity",
        "control-ref",
        "surrogate-ref",
        "invalid-utf8",
        "cdata",
    ] {
        case(&format!("results-hostile-{shape}"), &["results", "--output", &format!("{SCANS}/hostile/{shape}.nessus")]);
    }
}

#[test]
fn several_files_run_one_after_another_and_a_bad_one_doesnt_stop_the_rest() {
    let r = run(
        &["results", "testdata/scans/hostile/doctype.nessus", "testdata/scans/compliance.nessus", "nope.nessus"],
        b"",
    );
    assert_eq!(r.code, 1);
    assert_eq!(lines(&r.stdout).len(), 1);
    assert!(r.stderr.contains("refusing a DOCTYPE") && r.stderr.contains("nope.nessus: can't read"), "{}", r.stderr);
}

#[test]
fn reads_xml_from_stdin() {
    let xml = std::fs::read("testdata/scans/compliance.nessus").unwrap();
    let r = run(&["results"], &xml);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(lines(&r.stdout)[0]["scan"]["file"], "-");
    assert_eq!(run(&["results", "-", "-"], b"").code, 2);
    assert_eq!(run(&["results", "--min-severity", "5", "x"], b"").code, 2);
}
