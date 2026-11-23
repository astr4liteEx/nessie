//! The starter extensions in extensions/, run through nessie as a user
//! would. Skipped, with a message, without jq 1.7 or later.

mod common;
use common::Run;
use common::golden::check;
use std::io::Write;
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_nessie");
const PRO10: &str = "testdata/scans/pro-10.nessus";

fn have_jq() -> bool {
    let ok = Command::new("jq").arg("--version").output().is_ok_and(|o| {
        let v = String::from_utf8_lossy(&o.stdout);
        v.trim()
            .strip_prefix("jq-1.")
            .and_then(|m| m.split(['.', '-']).next()?.parse::<u32>().ok())
            .is_some_and(|m| m >= 7)
    });
    if !ok {
        eprintln!("skipping the starter extension tests: they need jq 1.7 or later");
    }
    ok
}

/// Runs `nessie args…` with extensions/ first on PATH and `stdin` piped in.
fn nessie(args: &[&str], stdin: &[u8]) -> Run {
    let dir = format!("{}/extensions", env!("CARGO_MANIFEST_DIR"));
    let path = format!("{dir}:{}", std::env::var("PATH").unwrap_or_default());
    let mut child = Command::new(BIN)
        .args(args)
        .env("PATH", path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    let o = child.wait_with_output().unwrap();
    Run {
        code: o.status.code().unwrap_or(-1),
        stdout: String::from_utf8(o.stdout).unwrap(),
        stderr: String::from_utf8(o.stderr).unwrap(),
    }
}

fn case(name: &str, args: &[&str]) -> Run {
    let r = nessie(args, b"");
    for rec in common::lines(&r.stdout) {
        common::schema::validate(&rec);
    }
    check(name, &r);
    r
}

#[test]
fn starter_goldens() {
    if !have_jq() {
        return;
    }
    case("services-pro-10", &["services", PRO10]);
    case(
        "services-two-scans",
        &["services", PRO10, "testdata/scans/compliance.nessus", "testdata/scans/edge-identity.nessus"],
    );
    case("scope-two-scans", &["scope", PRO10, "testdata/scans/edge-identity.nessus"]);
    case("filter-host-severity", &["filter", "--host", "192.0.2.0/30,192.0.2.20", "--min-severity", "2", PRO10]);
    case("filter-cve-where", &["filter", "--cve", "cve-2026-0001", "--where", ".port > 0", PRO10]);
    case("search-ignore-case", &["search", "-i", "SELF-SIGNED", PRO10]);
    case("search-in-cve", &["search", "--in", "cve", "CVE-2026-000[12]", PRO10]);
}

#[test]
fn a_stream_gives_what_the_scan_gives() {
    if !have_jq() {
        return;
    }
    let stream = nessie(&["results", "--output", PRO10], b"").stdout;
    for verb in ["services", "scope"] {
        assert_eq!(nessie(&[verb], stream.as_bytes()).stdout, nessie(&[verb, PRO10], b"").stdout, "{verb}");
    }
    let from_stream = nessie(&["search", "-i", "tls"], stream.as_bytes()).stdout;
    assert_eq!(from_stream, nessie(&["search", "-i", "tls", PRO10], b"").stdout);
    assert!(!from_stream.is_empty());
}

#[test]
fn other_kinds_pass_through_byte_for_byte_and_bad_lines_are_reported() {
    if !have_jq() {
        return;
    }
    let finding = "{\"kind\":\"finding\",\"title\":\"caf\\u00e9\",  \"n\":1.0}";
    let mut input = format!("{finding}\nnot json\n\n[1]\n");
    input.push_str(&nessie(&["results", PRO10], b"").stdout);
    for (verb, args) in [("filter", vec!["--plugin-id", "57582"]), ("search", vec!["Self-Signed"])] {
        let mut a = vec![verb];
        a.extend(args);
        let r = nessie(&a, input.as_bytes());
        assert_eq!(r.code, 1, "{verb}: {}", r.stderr);
        assert_eq!(r.stdout.lines().next(), Some(finding), "{verb}");
        assert_eq!(
            r.stderr,
            format!("nessie-{verb}: -:2: not a JSON object\nnessie-{verb}: -:4: not a JSON object\n"),
            "{verb}"
        );
        assert_eq!(common::lines(&r.stdout).iter().filter(|r| r["kind"] == "nessus-result").count(), 3, "{verb}");
    }
}

#[test]
fn usage_errors_exit_2() {
    if !have_jq() {
        return;
    }
    for args in [
        vec!["filter", "--port", "22,abc"],
        vec!["filter", "--min-severity", "5"],
        vec!["filter", "--where", ".port >"],
        vec!["filter", "--bogus"],
        vec!["search"],
        vec!["search", "("],
        vec!["services", "--bogus"],
    ] {
        let r = nessie(&args, b"");
        assert_eq!(r.code, 2, "{args:?}: {}", r.stderr);
        assert!(r.stderr.starts_with(&format!("nessie-{}: ", args[0])), "{}", r.stderr);
    }
}

#[test]
fn each_describes_itself_without_jq() {
    for verb in ["filter", "search", "services", "scope"] {
        // No jq on this PATH: --describe and --help still answer.
        let dir = format!("{}/extensions", env!("CARGO_MANIFEST_DIR"));
        let o = Command::new(format!("{dir}/nessie-{verb}"))
            .arg("--describe")
            .env("PATH", "/usr/bin/nonexistent:/bin")
            .output();
        // bash itself is in /bin or /usr/bin; with neither, skip.
        let Ok(o) = o else { continue };
        let d: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("{verb}: {e}"));
        assert_eq!(d["output"], "records", "{verb}");
        assert_eq!(d["version"], "0.0.0-dev", "{verb}");
    }
    let r = nessie(&["help"], b"");
    for verb in ["filter", "search", "services", "scope"] {
        assert!(r.stdout.contains(&format!("\"name\":\"{verb}\",\"source\":\"extension\"")), "{verb}");
    }
}

#[test]
fn stamped_extensions_work_alone_as_gah_installs_them() {
    if !have_jq() {
        return;
    }
    // gah puts every executable flat in one folder: no nessie.jq beside them.
    let dir = std::env::temp_dir().join(format!("nessie-gah-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy(BIN, dir.join("nessie")).unwrap();
    let root = env!("CARGO_MANIFEST_DIR");
    for verb in ["filter", "search", "services", "scope"] {
        let out = Command::new(format!("{root}/scripts/stamp-extension.sh"))
            .args([&format!("{root}/extensions/nessie-{verb}"), "9.8.7"])
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let p = dir.join(format!("nessie-{verb}"));
        std::fs::write(&p, &out.stdout).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let path = format!("{}:/usr/bin:/bin", dir.display());
    let run = |args: &[&str]| Command::new(dir.join("nessie")).args(args).env("PATH", &path).output().unwrap();
    let o = run(&["services", PRO10]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(String::from_utf8_lossy(&o.stdout), nessie(&["services", PRO10], b"").stdout);
    let o = run(&["filter", "--describe"]);
    assert!(String::from_utf8_lossy(&o.stdout).contains("\"version\":\"9.8.7\""));
    let _ = std::fs::remove_dir_all(&dir);
}
