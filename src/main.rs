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
        };
        nessie::run(&args, &mut io)
    };
    // A closed pipe downstream is not nessie's problem to report.
    let _ = out.flush();
    std::process::exit(code);
}
