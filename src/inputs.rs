//! Turning a verb's arguments into the inputs it reads: files, or `-` for
//! stdin. With no arguments, stdin is read when it isn't a terminal.

use crate::cli::Ctx;
use std::fs::File;
use std::io::Read;

/// The inputs named on the command line, checked for usage errors.
pub fn names(positional: &[String], ctx: &Ctx) -> Result<Vec<String>, String> {
    let names: Vec<String> = if positional.is_empty() {
        if ctx.stdin_tty {
            return Err("no input: name a scan, or pipe one in".into());
        }
        vec!["-".into()]
    } else {
        positional.to_vec()
    };
    if names.iter().filter(|n| *n == "-").count() > 1 {
        return Err("stdin can be read once: give - at most once".into());
    }
    Ok(names)
}

/// Opens a named input. Stdin is borrowed from the context.
pub fn open<'a>(name: &str, stdin: &'a mut dyn std::io::BufRead) -> std::io::Result<Box<dyn Read + 'a>> {
    if name == "-" { Ok(Box::new(stdin)) } else { Ok(Box::new(File::open(name)?)) }
}
