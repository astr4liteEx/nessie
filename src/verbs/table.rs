//! `nessie table`: records on stdin drawn as tables on a terminal, passed
//! through unchanged otherwise.

use crate::cli::{Args, Ctx};
use crate::diag::Loc;
use crate::jsonl::{Item, Reader};
use crate::table::{Tables, problem_text};

pub fn run(args: &Args, ctx: &mut Ctx) -> i32 {
    if !args.positional.is_empty() {
        return super::usage(ctx, "table", "table reads stdin only");
    }
    if !ctx.stdout_tty || args.has("json") {
        return pass_through(ctx);
    }
    let mut t = Tables::new(false);
    let mut r = Reader::new(&mut *ctx.stdin);
    loop {
        match r.next_item() {
            Ok(Some(Item::Record(rec))) => {
                if let Err(e) = t.line(&rec.raw) {
                    ctx.diag.error(Loc::line("-", rec.line), e);
                }
                for p in t.problems.drain(..) {
                    ctx.diag.note(&problem_text(&p));
                }
            }
            Ok(Some(Item::Malformed { line, reason })) => ctx.diag.error(Loc::line("-", line), reason),
            Ok(None) => break,
            Err(e) => {
                ctx.diag.error(Loc::path("-"), format!("can't read: {e}"));
                break;
            }
        }
    }
    if ctx.stdout.write_all(t.render(ctx.style).as_bytes()).is_err() {
        return ctx.diag.code().max(crate::exit::PROBLEMS);
    }
    ctx.diag.code()
}

/// Copies stdin to stdout byte for byte, line by line.
fn pass_through(ctx: &mut Ctx) -> i32 {
    let mut line = Vec::new();
    loop {
        line.clear();
        match ctx.stdin.read_until(b'\n', &mut line) {
            Ok(0) => return ctx.diag.code(),
            Ok(_) => {
                if ctx.stdout.write_all(&line).is_err() {
                    return ctx.diag.code();
                }
            }
            Err(e) => {
                ctx.diag.error(Loc::path("-"), format!("can't read: {e}"));
                return ctx.diag.code();
            }
        }
    }
}
