use std::io::{self, IsTerminal, Write};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let stdin = io::stdin();
    let stdout = io::stdout();
    let stdin_tty = stdin.is_terminal();
    let stdout_tty = stdout.is_terminal();
    let mut out = io::BufWriter::new(stdout.lock());
    let code = {
        let mut io = nessie::Io {
            stdin: &mut stdin.lock(),
            stdout: &mut out,
            stderr: &mut io::stderr().lock(),
            stdin_tty,
            stdout_tty,
            style: nessie::table::Style { color: color(), width: width() },
        };
        nessie::run(&args, &mut io)
    };
    // A closed pipe downstream is not nessie's problem to report.
    let _ = out.flush();
    std::process::exit(code);
}

/// Colour unless NO_COLOR is set (to anything) or the terminal is dumb.
fn color() -> bool {
    let set = |k: &str| std::env::var_os(k).is_some_and(|v| !v.is_empty());
    !set("NO_COLOR") && std::env::var_os("TERM").is_none_or(|t| t != "dumb")
}

/// stdout's width in columns, or 0 when it isn't a terminal.
fn width() -> usize {
    terminal_size::terminal_size_of(io::stdout()).map_or(0, |(w, _)| usize::from(w.0))
}
