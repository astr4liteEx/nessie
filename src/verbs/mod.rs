//! The built-in verbs. Each is described here; its code lives in its own module.

use crate::cli::{Args, Ctx, MIN_SEVERITY, OUTPUT, Verb};
use crate::diag::Loc;

mod version;

/// The built-in verbs, in the order help lists them.
pub static ALL: &[Verb] = &[
    Verb {
        name: "results",
        summary: "Emit one record per Result in .nessus scans",
        usage: "nessie results [--output] [--min-severity N] <scan.nessus>... | -",
        input: Some("xml/nessus"),
        output: Some("records"),
        roles: &["source"],
        flags: &[OUTPUT, MIN_SEVERITY],
        notes: "",
        run: not_built,
    },
    Verb {
        name: "hosts",
        summary: "Emit one record per Host, with every HostProperties tag",
        usage: "nessie hosts <scan.nessus>... | -",
        input: Some("xml/nessus"),
        output: Some("records"),
        roles: &["source"],
        flags: &[],
        notes: "",
        run: not_built,
    },
    Verb {
        name: "scan",
        summary: "Summarise each scan: names, server preferences, counts and scanner version",
        usage: "nessie scan <scan.nessus>... | -",
        input: Some("xml/nessus"),
        output: Some("records"),
        roles: &["source"],
        flags: &[],
        notes: "",
        run: not_built,
    },
    Verb {
        name: "items",
        summary: "Group Results by Nessus plugin",
        usage: "nessie items [--output] [--min-severity N] [<scan.nessus>... | -]",
        input: Some("xml/nessus"),
        output: Some("records"),
        roles: &["source", "filter"],
        flags: &[OUTPUT, MIN_SEVERITY],
        notes: "",
        run: not_built,
    },
    Verb {
        name: "merge",
        summary: "Merge scans or Result streams; the later input wins",
        usage: "nessie merge [--output] [--min-severity N] [<scan.nessus|results.jsonl>... | -]",
        input: Some("xml/nessus"),
        output: Some("records"),
        roles: &["source", "filter"],
        flags: &[OUTPUT, MIN_SEVERITY],
        notes: "",
        run: not_built,
    },
    Verb {
        name: "diff",
        summary: "Compare two scans: new, fixed, present and host-missing Results",
        usage: "nessie diff [--output] [--min-severity N] <old> <new>",
        input: Some("xml/nessus"),
        output: Some("records"),
        roles: &["source"],
        flags: &[OUTPUT, MIN_SEVERITY],
        notes: "",
        run: not_built,
    },
    Verb {
        name: "table",
        summary: "Print records as tables on a terminal; pass them through otherwise",
        usage: "nessie table < records.jsonl",
        input: Some("records"),
        output: Some("records"),
        roles: &["sink", "filter"],
        flags: &[],
        notes: "",
        run: not_built,
    },
    Verb {
        name: "version",
        summary: "Print nessie's version and its record schema versions",
        usage: "nessie version",
        input: None,
        output: Some("records"),
        roles: &[],
        flags: &[],
        notes: "",
        run: version::run,
    },
];

/// The built-in verb named `name`.
pub fn find(name: &str) -> Option<&'static Verb> {
    ALL.iter().find(|v| v.name == name)
}

fn not_built(_: &Args, ctx: &mut Ctx) -> i32 {
    ctx.diag.error(Loc::none(), "this verb is not built yet");
    ctx.diag.code()
}
