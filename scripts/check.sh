#!/bin/sh
# The gate every commit passes: format, lint, tests, dependency audit.
# With --perf, then the speed and memory check on a large synthetic scan
# (scripts/perf.py; a few minutes, and about 1 GB of temporary disk).
set -eu
cd "$(dirname "$0")/.."
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test -q
if command -v cargo-audit >/dev/null 2>&1; then
    cargo audit -q
else
    echo "check: cargo-audit not installed (cargo install cargo-audit); the audit is part of the gate" >&2
    exit 1
fi
if [ "${1:-}" = --perf ]; then
    python3 -I scripts/perf.py
fi
