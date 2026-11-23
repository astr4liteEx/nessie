<div align="center">

# nessie

**Read Nessus scans and emit what is in them as JSON Lines records.**

[![CI](https://github.com/astr4liteEx/nessie/actions/workflows/ci.yml/badge.svg)](https://github.com/astr4liteEx/nessie/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Rust 1.99+](https://img.shields.io/badge/rust-1.99%2B-orange.svg)
![Linux amd64 | arm64](https://img.shields.io/badge/platform-linux%20amd64%20%7C%20arm64-lightgrey.svg)

[Features](#features) • [Install](#install) • [Quick start](#quick-start) • [Commands](#commands) • [Records](#records) • [Extensions](#extensions) • [Recipes](#recipes) • [Development](#development)

</div>

nessie turns a Nessus `.nessus` export into one JSON record per line, for jq and other tools to chain on. Records keep the scan's own values without loss. nessie doesn't correlate, tag or write findings: it is the converter in front of the tools that do.

![nessie scan summarising a scan, then nessie items listing its Nessus plugins from critical down, as tables](docs/demo/quick-start.gif)

## Features

- **Streaming:** a 400 MB scan converts in about 3 s at flat memory (12 MB). The Policy section, often most of the file, is skipped without being read into memory.
- **Lossless:** every ReportItem element is kept in `elements`, plugin output is opt-in with `--output`, and records of other kinds pass through untouched.
- **Chainable:** JSON Lines in a pipe, tables on a terminal, `--describe` for every verb, and exit codes that tell problems from usage errors. It doubles as an [rpt](https://github.com/astr4liteEx/rpt) plugin.
- **Scan to scan:** `merge` de-duplicates scans of the same network, and `diff` marks each Result new, fixed, still present or on a Host that wasn't scanned.
- **Extensible:** any `nessie-<verb>` on `PATH` runs as `nessie <verb>`. The starters (`services`, `filter`, `search`, `scope`) are bash and jq.

## Install

nessie runs on Linux (amd64 and arm64). The binary is static and needs nothing else.

> [!NOTE]
> The starter extensions need bash and [jq](https://jqlang.org) 1.7 or newer. Without jq, the built-in commands still work.

### With gah

[gah](https://github.com/get-gah/gah) downloads the release archive, checks its digest and installs `nessie` and the starter extensions to `~/.local/bin` (add `--tag=<version>` for a specific release):

```sh
gah install astr4liteEx/nessie --unattended
ln -s nessie ~/.local/bin/rpt-nessus    # optional: run it as `rpt nessus`
```

### From a release

Download the archive for your machine and `SHA256SUMS` from the [releases](https://github.com/astr4liteEx/nessie/releases), then check, unpack and install:

```sh
sha256sum -c --ignore-missing SHA256SUMS
tar -xzf nessie_0.1.0_linux_amd64.tar.gz
sh nessie_0.1.0_linux_amd64/install.sh    # into ~/.local/bin; --prefix DIR, --rpt for rpt-nessus
```

`install.sh` only copies `bin/*`, so `cp nessie_0.1.0_linux_amd64/bin/* ~/.local/bin/` does the same. `schema/` holds the record schemas, for reference.

### With cargo

Requires Rust 1.99 or newer. This builds `nessie` only; the extensions are in [`extensions/`](extensions) and need `nessie.jq` beside them.

```sh
cargo install --git https://github.com/astr4liteEx/nessie --tag v0.1.0 --locked
```

## Quick start

```sh
nessie scan scan.nessus                      # what the scan is: names, versions, counts
nessie items --min-severity medium scan.nessus    # medium and above, one row per Nessus plugin
nessie results scan.nessus | jq -c 'select(.severity >= 3)' | nessie items
```

On a terminal each command prints a table; piped, it prints JSON Lines. Add `--json` to get JSON on a terminal too.

> [!TIP]
> Most of a big scan is informational Results. `--min-severity low` drops them while reading, before anything else sees them.

## Commands

```
nessie <verb> [flags] [scan.nessus...]
```

| Verb | Reads | Emits |
| --- | --- | --- |
| `results` | scans | one `nessus-result` per ReportItem: the base stream |
| `hosts` | scans | one `nessus-host` per ReportHost, every HostProperties tag and its Result counts |
| `scan` | scans | one `nessus-scan` per file: names, server preferences, counts, Nessus and feed versions |
| `items` | scans or results | one `nessus-item` per Nessus plugin, with each Host and its endpoints |
| `merge` | scans or results | Results de-duplicated across scans, the later scan winning |
| `diff <old> <new>` | scans or results | each Result marked `new`, `present` (with what `changed`), `fixed` or `host-missing` |
| `table` | records | records as tables on a terminal; unchanged otherwise |
| `help [verb]` | | the built-ins and the extensions on `PATH` |
| `version` | | nessie's version and its record schema versions |

Inputs are files, or stdin when none are named (`-` names it once). A scan and a results stream are told apart by their first byte, so `items`, `merge` and `diff` take either. There is no decompression: pipe it in.

```sh
zcat scan.nessus.gz | nessie results
unzip -p export.zip scan.nessus | nessie scan
```

**Flags.** `--output` adds each Result's `plugin_output` (on `results`, `items`, `merge` and `diff`). `--min-severity` drops lower Results while reading; it takes `info`, `low`, `medium`, `high` or `critical`, or Nessus's numbers 0 to 4. `--json` prints JSON Lines on a terminal. Every verb takes `--help` and `--describe`.

**Exit codes.** 0 when all went well; 1 when the input had problems, reported on stderr with file and line while nessie carries on with the next record or file; 2 for usage errors. `diff` exits 0 whatever changed: test its output with `jq -e`.

**Tables.** On a terminal, records show as tables sorted most severe first, with severities named and coloured, following `NO_COLOR` and `TERM=dumb`.

### Comparing scans

`nessie diff` holds the older scan and streams the newer one against it. A Result only in the older scan is `fixed` if its Host was scanned again, and `host-missing` if it wasn't, so a Host left out of a retest never looks fixed.

![nessie diff between two monthly scans, then the same diff filtered with jq to what changed and drawn with nessie table](docs/demo/diff.gif)

### Chains

> [!IMPORTANT]
> Run chains with `set -o pipefail`. Without it, a nessie that failed halfway looks like an empty result.

```sh
set -o pipefail
nessie results --output scan.nessus | jq -c 'select(.plugin_id == 22869)' > inventory.jsonl
```

For a large scan you'll query more than once, convert it once and work from the file: `nessie results --output scan.nessus > scan.jsonl`.

## Records

Every record has `kind` and `schema_version`; the schemas are in [`schema/`](schema). A `nessus-result` looks like this (trimmed):

```json
{"kind":"nessus-result","schema_version":1,
 "scan":{"file":"scan.nessus","name":"Weekly"},
 "host":{"name":"192.0.2.10","ip":"192.0.2.10","fqdn":"web.example.test"},
 "port":443,"protocol":"tcp","svc_name":"www","severity":2,
 "plugin_id":57582,"plugin_name":"SSL Self-Signed Certificate","plugin_family":"General",
 "elements":{"cvss3_base_score":["6.5"],"risk_factor":["Medium"],"synopsis":["..."]},
 "plugin_output":"..."}
```

- `severity` is Nessus's own number, 0 to 4: info, low, medium, high and critical. Tables show the names; records keep the number, so `jq 'select(.severity >= 3)'` means high and above.
- `elements` holds every child element of the ReportItem as a list of strings: repeated elements (`cve`, `bid`, `xref`) collect, and `cpe` and `see_also` split on newlines.
- `host.fqdn` and `host.ip` come from the `host-fqdn` and `host-ip` tags, when present.
- `merge` and `diff` match Hosts on fqdn, then ip, then name, and Results on Host, `plugin_id`, `port` and `protocol`.
- An Item whose line would pass 16 MiB (a big inventory plugin with `--output`) is split into parts, each with `part: {index, count}`; merge them by `plugin_id`. To avoid parts altogether, stay with `results --output`, where each line is one Result.

What nessie leaves out (the Policy's plugin preferences, attachments' attributes) is still in the XML, for `xmllint --xpath` or `xq`:

```sh
xmllint --xpath 'string(//ReportItem[@pluginID="19506"]/plugin_output)' scan.nessus
```

## Extensions

`nessie <verb>` runs a built-in if there is one, otherwise the first `nessie-<verb>` on `PATH`, with the same arguments, stdin and stdout, and `NESSIE_BIN` set to nessie's own path. On a terminal, an extension whose `--describe` says `"output":"records"` is drawn as tables too. `nessie help` lists them all. The protocol is [rpt's](https://github.com/astr4liteEx/rpt/blob/main/docs/plugin-protocol.md).

The starters take scans (read through `nessie results`) or a results stream:

| Extension | What it does |
| --- | --- |
| `nessie services` | one `nessus-service` per Host, port and protocol, with the plugins that fired there; `svc_name` from Service Detection when it ran |
| `nessie filter` | keeps matching Results: `--plugin-id`, `--family`, `--host` (name, ip, fqdn or IPv4 CIDR), `--port`, `--protocol`, `--cve`, `--min-severity`, `--max-severity`, `--exploit-available`, `--where '<jq>'`. Comma lists match any; flags must all match |
| `nessie search` | keeps Results whose name, elements or output match a regex; `-i`, `--in cve,synopsis` |
| `nessie scope` | one rpt `scope` record per Host: `nessie scope scan.nessus \| rpt scope add` |

![nessie services listing each Host's open ports, nessie filter picking two CVEs into nessie items, and a unique CVE list from jq](docs/demo/extensions.gif)

## Recipes

Web services for [nuclei](https://github.com/projectdiscovery/nuclei):

```sh
nessie services scan.nessus \
  | jq -r 'select(.svc_name | test("^(www|https?)$")) | "\(.host.fqdn // .host.ip // .host.name):\(.port)"' \
  | nuclei -l -
```

Every CVE in a scan, once:

```sh
nessie results scan.nessus | jq -r '.elements.cve[]?' | sort -u
```

Hosts and their operating system:

```sh
nessie hosts scan.nessus \
  | jq -r '[.host.fqdn // .host.ip // .host.name, (.properties["operating-system"] // "" | split("\n")[0])] | @tsv'
```

Hosts on a subnet with a given OpenSSH flaw:

```sh
nessie filter --host 10.0.0.0/24 --cve CVE-2024-6387 scan.nessus | jq -r '.host.ip' | sort -u
```

What changed since the last scan, severity changes included:

```sh
nessie diff last.nessus this.nessus | jq -c 'select(.diff.state != "present" or (.diff.changed | length > 0))'
```

## Development

```sh
scripts/check.sh           # the gate, as CI runs it: fmt, clippy, tests, cargo audit
scripts/check.sh --perf    # then speed and memory on a ~400 MB synthetic scan
UPDATE_GOLDEN=1 cargo test # rewrite testdata/golden; review the diff
```

Test scans in `testdata/scans` are hand-written, with documentation addresses and `example.test` names; `scripts/gen-scan.py` makes large synthetic ones. `scripts/release.sh` builds the release archives on a `v` tag, and pushing the tag publishes them.

The demo GIFs are recorded with [VHS](https://github.com/charmbracelet/vhs) against invented scans:

```sh
docs/demo/setup.sh && vhs docs/demo/quick-start.tape    # or extensions.tape, diff.tape
```
