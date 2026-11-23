mod common;
use common::golden::case;
use common::{lines, run};

const OLD: &str = "testdata/scans/retest-old.nessus";
const NEW: &str = "testdata/scans/retest-new.nessus";

#[test]
fn merge_and_diff_golden() {
    case("merge-retest", &["merge", OLD, NEW]);
    case("diff-retest", &["diff", OLD, NEW]);
    case("diff-output-retest", &["diff", "--output", OLD, NEW]);
}

fn states(out: &str) -> Vec<(String, u64)> {
    lines(out)
        .iter()
        .map(|r| (r["diff"]["state"].as_str().unwrap().to_string(), r["plugin_id"].as_u64().unwrap()))
        .collect()
}

#[test]
fn diff_states_on_the_retest_pair() {
    let r = run(&["diff", OLD, NEW], b"");
    assert_eq!(r.code, 0, "{}", r.stderr);
    let s = states(&r.stdout);
    let has = |st: &str, id: u64| s.contains(&(st.to_string(), id));
    assert!(has("present", 57582), "severity changed, still present");
    assert!(has("present", 201010), "matched on fqdn though the IP changed");
    assert!(has("new", 10107));
    assert!(has("fixed", 104743));
    assert!(has("host-missing", 156899), "an unscanned Host never reads as fixed");
    let sev = lines(&r.stdout).into_iter().find(|r| r["plugin_id"] == 57582).unwrap();
    assert_eq!(sev["diff"]["changed"], serde_json::json!(["severity"]));
}

#[test]
fn diff_with_output_names_a_changed_output() {
    let r = run(&["diff", "--output", OLD, NEW], b"");
    let rec = lines(&r.stdout).into_iter().find(|r| r["plugin_id"] == 57582).unwrap();
    assert_eq!(rec["diff"]["changed"], serde_json::json!(["severity", "plugin_output"]));
}

#[test]
fn diff_reads_a_stream_on_either_side() {
    let old = run(&["results", OLD], b"").stdout;
    let from_stream = run(&["diff", "-", NEW], old.as_bytes());
    let from_scan = run(&["diff", OLD, NEW], b"");
    assert_eq!(states(&from_stream.stdout), states(&from_scan.stdout));
}

#[test]
fn diff_against_itself_is_all_present_and_unchanged() {
    let r = run(&["diff", NEW, NEW], b"");
    assert!(lines(&r.stdout).iter().all(|r| r["diff"] == serde_json::json!({"state":"present","changed":[]})));
}

#[test]
fn diff_usage() {
    assert_eq!(run(&["diff", OLD], b"").code, 2);
    assert_eq!(run(&["diff", "-", "-"], b"").code, 2);
}

#[test]
fn merge_is_idempotent_and_a_stream_merges_like_scans() {
    let once = run(&["merge", OLD, NEW], b"").stdout;
    assert_eq!(run(&["merge"], once.as_bytes()).stdout, once);
    // A results stream keeps each record's scan.file, so it merges the same.
    let both = run(&["results", OLD, NEW], b"").stdout;
    assert_eq!(run(&["merge"], both.as_bytes()).stdout, once);
}
