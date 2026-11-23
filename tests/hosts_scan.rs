mod common;
use common::golden::case;
use common::run;

const SHAPES: &[&str] = &["pro-10", "pro-5", "vm-export", "compliance", "edge-identity", "empty-report", "policy-only"];

#[test]
fn hosts_for_every_fixture() {
    for shape in SHAPES {
        case(&format!("hosts-{shape}"), &["hosts", &format!("testdata/scans/{shape}.nessus")]);
    }
}

#[test]
fn scan_for_every_fixture() {
    for shape in SHAPES {
        case(&format!("scan-{shape}"), &["scan", &format!("testdata/scans/{shape}.nessus")]);
    }
}

#[test]
fn hosts_and_scan_refuse_a_records_stream() {
    let records = run(&["results", "testdata/scans/compliance.nessus"], b"").stdout;
    for verb in ["hosts", "scan"] {
        let r = run(&[verb], records.as_bytes());
        assert_eq!(r.code, 1, "{verb}");
        assert!(r.stderr.contains("this is a JSON Lines stream"), "{}", r.stderr);
    }
}

#[test]
fn a_compressed_scan_gets_a_hint() {
    let r = run(&["scan"], b"\x1f\x8b\x08\x00");
    assert_eq!(r.code, 1);
    assert!(r.stderr.contains("zcat"), "{}", r.stderr);
}
