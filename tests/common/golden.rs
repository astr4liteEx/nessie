//! Golden files: `testdata/golden/<name>.jsonl` (or `.txt` for a terminal
//! table) holds stdout and `<name>.err` the exit code and stderr. `UPDATE_GOLDEN=1 cargo test`
//! rewrites them; review the diff by hand.

use super::Run;
use std::path::PathBuf;

fn path(name: &str, ext: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/golden").join(format!("{name}.{ext}"))
}

pub fn check(name: &str, r: &Run) {
    check_as(name, "jsonl", r);
}

/// `check` with stdout in `<name>.<ext>`.
pub fn check_as(name: &str, out_ext: &str, r: &Run) {
    let err = format!("exit {}\n{}", r.code, r.stderr);
    for (ext, got) in [(out_ext, &r.stdout), ("err", &err)] {
        let p = path(name, ext);
        if std::env::var_os("UPDATE_GOLDEN").is_some() {
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, got).unwrap();
            continue;
        }
        let want = std::fs::read_to_string(&p)
            .unwrap_or_else(|_| panic!("{} is missing: run UPDATE_GOLDEN=1 cargo test", p.display()));
        assert!(
            *got == want,
            "{} differs from the golden file; run UPDATE_GOLDEN=1 cargo test and review:\n--- got\n{got}",
            p.display()
        );
    }
}

/// Runs nessie, validates every record it prints, and checks the golden files.
pub fn case(name: &str, args: &[&str]) -> Run {
    let r = super::run(args, b"");
    for rec in super::lines(&r.stdout) {
        super::schema::validate(&rec);
    }
    check(name, &r);
    r
}
