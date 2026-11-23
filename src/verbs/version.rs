//! `nessie version`: an rpt `version` record (kind, version, schema_version,
//! format), plus nessie's name and each record kind's schema_version.

use crate::cli::{Args, Ctx};
use crate::jsonl;
use serde_json::json;

/// The generation of nessie's record schemas: rpt's `schema_version`. It
/// moves when any kind's does, so it is the highest of them.
pub const SCHEMA_VERSION: u64 = 1;

/// The input format nessie reads, rpt's `format`: NessusClientData_v2.
pub const FORMAT: u64 = 2;

/// The schema_version of every kind nessie owns.
pub const SCHEMA_VERSIONS: &[(&str, u64)] =
    &[("nessus-result", 1), ("nessus-item", 1), ("nessus-host", 1), ("nessus-scan", 1), ("nessus-service", 1)];

pub fn run(_: &Args, ctx: &mut Ctx) -> i32 {
    let schemas: serde_json::Map<_, _> = SCHEMA_VERSIONS.iter().map(|(k, v)| (k.to_string(), json!(v))).collect();
    let rec = json!({
        "kind": "version",
        "name": "nessie",
        "version": crate::VERSION,
        "schema_version": SCHEMA_VERSION,
        "format": FORMAT,
        "schema_versions": schemas,
    });
    if jsonl::write_value(ctx.stdout, &rec).is_err() {
        return crate::exit::PROBLEMS;
    }
    ctx.diag.code()
}
