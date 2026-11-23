#!/usr/bin/env python3
"""Speed and memory check on a large synthetic scan: scripts/check.sh --perf.

Builds a release nessie, generates a ~400 MB scan with gen-scan.py (1850 Hosts) (Policy
at 60%, and an inventory Nessus plugin big enough that its Item splits),
then checks:
  - results streams at flat memory (peak under 64 MB);
  - items on the whole scan finishes, its peak reported;
  - items --output splits the inventory Item into parts under 16 MiB.
Run with python3 -I. The scan goes in a temporary folder and is removed.
"""
import json
import os
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NESSIE = os.path.join(ROOT, "target", "release", "nessie")
MAX_LINE = 16 * 1024 * 1024
FLAT_MB = 64


def run(args, out):
    """Runs nessie; returns (exit code, seconds, peak RSS in MB)."""
    start = time.monotonic()
    p = subprocess.Popen([NESSIE] + args, stdout=out, stderr=subprocess.PIPE)
    _, status, usage = os.wait4(p.pid, 0)
    secs = time.monotonic() - start
    err = p.stderr.read().decode(errors="replace")
    code = os.waitstatus_to_exitcode(status)
    if code != 0:
        sys.exit(f"perf: nessie {' '.join(args)} exited {code}:\n{err}")
    return secs, usage.ru_maxrss / 1024


def main():
    subprocess.run(["cargo", "build", "--release", "-q"], cwd=ROOT, check=True)
    failed = False
    with tempfile.TemporaryDirectory(prefix="nessie-perf-") as tmp:
        scan = os.path.join(tmp, "big.nessus")
        with open(scan, "w") as f:
            subprocess.run(
                [sys.executable, "-I", os.path.join(ROOT, "scripts", "gen-scan.py"),
                 "--hosts", "1850", "--inventory-kb", "16"],
                stdout=f, check=True)
        size = os.path.getsize(scan) / 1e6
        print(f"scan: {size:.0f} MB")

        secs, mb = run(["results", scan], subprocess.DEVNULL)
        ok = mb < FLAT_MB
        failed |= not ok
        print(f"results          {secs:6.1f} s  {mb:6.0f} MB peak  {'ok' if ok else f'FAIL: over {FLAT_MB} MB'}")

        secs, mb = run(["items", scan], subprocess.DEVNULL)
        print(f"items            {secs:6.1f} s  {mb:6.0f} MB peak")

        out = os.path.join(tmp, "items.jsonl")
        with open(out, "wb") as f:
            secs, mb = run(["items", "--output", scan], f)
        parts, longest = 0, 0
        with open(out, "rb") as f:
            for line in f:
                longest = max(longest, len(line) - 1)
                rec = json.loads(line)
                if rec.get("plugin_id") == 22869 and "part" in rec:
                    parts += 1
        ok = parts >= 2 and longest <= MAX_LINE
        failed |= not ok
        print(f"items --output   {secs:6.1f} s  {mb:6.0f} MB peak  "
              f"{parts} parts, longest line {longest / 2**20:.1f} MiB  {'ok' if ok else 'FAIL'}")
    sys.exit(1 if failed else 0)


main()
