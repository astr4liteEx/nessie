mod common;
use common::golden::case;
use common::{lines, run};
use serde_json::{Value, json};

#[test]
fn items_golden() {
    case("items-pro-10", &["items", "testdata/scans/pro-10.nessus"]);
    case("items-output-pro-10", &["items", "--output", "testdata/scans/pro-10.nessus"]);
    case("items-two-scans", &["items", "testdata/scans/pro-10.nessus", "testdata/scans/pro-5.nessus"]);
    case("items-min-severity-pro-10", &["items", "--min-severity", "3", "testdata/scans/pro-10.nessus"]);
}

#[test]
fn a_results_stream_and_the_scan_give_the_same_items() {
    let stream = run(&["results", "--output", "testdata/scans/pro-10.nessus"], b"").stdout;
    let from_stream = run(&["items", "--output"], stream.as_bytes());
    let from_scan = run(&["items", "--output", "testdata/scans/pro-10.nessus"], b"");
    assert_eq!(from_stream.code, 0, "{}", from_stream.stderr);
    // Only scan.file differs: "-" against the path.
    assert_eq!(
        from_stream.stdout.replace("\"file\":\"testdata/scans/pro-10.nessus\"", "\"file\":\"-\""),
        from_scan.stdout.replace("\"file\":\"testdata/scans/pro-10.nessus\"", "\"file\":\"-\"")
    );
}

#[test]
fn other_kinds_pass_through_byte_for_byte_and_bad_lines_are_reported() {
    let mut input = String::from("{\"kind\":\"finding\",\"title\":\"caf\\u00e9\",  \"n\":1.0}\n");
    input.push_str("not json\n");
    input.push_str("{\"kind\":\"nessus-result\",\"schema_version\":2}\n");
    input.push_str(&run(&["results", "testdata/scans/compliance.nessus"], b"").stdout);
    let r = run(&["items"], input.as_bytes());
    assert_eq!(r.code, 1);
    let out: Vec<&str> = r.stdout.lines().collect();
    assert_eq!(out[0], "{\"kind\":\"finding\",\"title\":\"caf\\u00e9\",  \"n\":1.0}");
    assert_eq!(lines(&r.stdout)[1]["kind"], "nessus-item");
    assert!(r.stderr.contains("nessie: -:2: invalid JSON"), "{}", r.stderr);
    assert!(
        r.stderr.contains("nessie: -:3: dropping a record: nessus-result schema_version 2 is newer"),
        "{}",
        r.stderr
    );
}

#[test]
fn output_is_dropped_from_a_stream_without_the_flag() {
    let stream = run(&["results", "--output", "testdata/scans/pro-10.nessus"], b"").stdout;
    let r = run(&["items"], stream.as_bytes());
    assert!(!r.stdout.contains("plugin_output"));
}

#[test]
fn an_item_over_16_mib_is_split_into_parts_that_merge_back() {
    // 100 Hosts x 200 KB of inventory output: about 20 MB in one Item.
    let out = "  ii  synthetic-package  1.0.0-1  amd64  a synthetic package\n".repeat(3300);
    let mut stream = String::new();
    for i in 0..100 {
        let r = json!({"kind":"nessus-result","schema_version":1,"scan":{"file":"big"},
            "host":{"name":format!("10.0.0.{i}"),"ip":format!("10.0.0.{i}")},"port":0,"protocol":"tcp",
            "svc_name":"general","severity":0,"plugin_id":22869,"plugin_name":"Software Enumeration (SSH)",
            "plugin_family":"General","elements":{"synopsis":["s"]},"plugin_output":out});
        stream.push_str(&r.to_string());
        stream.push('\n');
    }
    let r = run(&["items", "--output"], stream.as_bytes());
    assert_eq!(r.code, 0, "{}", r.stderr);
    let recs = lines(&r.stdout);
    assert!(recs.len() >= 2, "{} records", recs.len());
    let mut hosts: Vec<Value> = Vec::new();
    for (i, rec) in recs.iter().enumerate() {
        common::schema::validate(rec);
        assert!(r.stdout.lines().nth(i).unwrap().len() <= 16 * 1024 * 1024);
        assert_eq!(rec["part"]["index"], i + 1);
        assert_eq!(rec["part"]["count"], recs.len());
        assert_eq!(rec["plugin_id"], 22869);
        hosts.extend(rec["hosts"].as_array().unwrap().iter().cloned());
    }
    assert_eq!(hosts.len(), 100);
    assert!(hosts.iter().all(|h| h["endpoints"][0]["plugin_output"] == json!(out)));
}
