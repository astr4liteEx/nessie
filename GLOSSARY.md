# nessie

nessie reads Nessus scans and emits what is in them as records, for other tools to chain on. It knows nothing about the tools downstream.

## Scans

**Scan**:
One Nessus scan's output, as a `.nessus` file.
_Avoid_: report (that is rpt's), export

**Nessus plugin**:
One of Nessus's checks, identified by its Nessus plugin ID. Always written in full: the bare word "plugin" means an rpt plugin.
_Avoid_: plugin (alone), check, test

**Nessus plugin ID**:
A Nessus plugin's stable number, the key every tool downstream matches on. The plugin's name changes between feed versions; its ID doesn't.
_Avoid_: plugin name (as a key), check ID

**Result**:
One Nessus plugin's output for one host and port, a `ReportItem` in the scan.
_Avoid_: finding (that is rpt's), vuln, issue, report item

**Item**:
All of one Nessus plugin's results in a scan, grouped, with the hosts and endpoints it fired on.
_Avoid_: aggregate, finding, group

**Diff state**:
How a Result in a retest compares with the earlier scan: new, fixed, present, or host-missing when its Host was not in the retest at all, so an unscanned Host is never read as fixed.
_Avoid_: status, delta

**Host**:
One scanned machine, a `ReportHost` in the scan, known by its FQDN, IP or the name Nessus gave it.
_Avoid_: asset, target (that is rpt's), scope row

**Service**:
One Host, port and protocol where the scan reported something, whatever Nessus plugin found it.
_Avoid_: port, endpoint (alone), listener

## nessie

**Record kind**:
The name of a record's schema, carried in its `kind` member. nessie's kinds are prefixed with the data they describe (`nessus-`), never with the tool's name.
_Avoid_: record type, nessie-* (that names executables)

**Extension**:
An executable named `nessie-<name>` that nessie runs for `nessie <name>` when it has no built-in verb of that name.
_Avoid_: plugin (that is rpt's), script, addon
