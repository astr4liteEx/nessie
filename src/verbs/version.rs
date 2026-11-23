//! `nessie version`: nessie's version and each record kind's schema_version.

use crate::cli::{Args, Ctx};
use crate::jsonl;
use serde_json::json;

/// The schema_version of every kind nessie owns.
pub const SCHEMA_VERSIONS: &[(&str, u64)] =
    &[("nessus-result", 1), ("nessus-item", 1), ("nessus-host", 1), ("nessus-scan", 1), ("nessus-service", 1)];

pub fn run(_: &Args, ctx: &mut Ctx) -> i32 {
    let schemas: serde_json::Map<_, _> = SCHEMA_VERSIONS.iter().map(|(k, v)| (k.to_string(), json!(v))).collect();
    let rec = json!({
        "kind": "version",
        "name": "nessie",
        "version": crate::VERSION,
        "schema_versions": schemas,
    });
    if jsonl::write_value(ctx.stdout, &rec).is_err() {
        return crate::exit::PROBLEMS;
    }
    ctx.diag.code()
}
