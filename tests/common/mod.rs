//! Runs nessie in-process with given stdin, returning (exit code, stdout, stderr).

#![allow(dead_code)]

pub struct Run {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

pub fn run(args: &[&str], stdin: &[u8]) -> Run {
    run_tty(args, stdin, false)
}

pub fn run_tty(args: &[&str], stdin: &[u8], stdout_tty: bool) -> Run {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let mut input = stdin;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = {
        let mut io = nessie::Io { stdin: &mut input, stdout: &mut out, stderr: &mut err, stdin_tty: false, stdout_tty };
        nessie::run(&args, &mut io)
    };
    Run { code, stdout: String::from_utf8(out).unwrap(), stderr: String::from_utf8(err).unwrap() }
}

/// Parses every stdout line as JSON.
pub fn lines(s: &str) -> Vec<serde_json::Value> {
    s.lines().map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{e}: {l}"))).collect()
}
