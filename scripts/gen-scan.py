#!/usr/bin/env python3
"""Generate a synthetic .nessus scan for speed and memory checks.

Usage:  python3 -I scripts/gen-scan.py --mb 400 [--hosts 2000] [--inventory-kb 0] > big.nessus

The shape follows testdata/scans/pro-10.nessus. Every value is invented
(192.0.2.0/24-style documentation addresses, example.test names). The Policy
section is padded to about --policy-share of the file (0.6 by default: in
real exports the Policy is often most of the file). With --inventory-kb N, each Host also gets one inventory Result
(Nessus plugin 22869) with N KB of output, which with enough Hosts pushes an
`items --output` record past 16 MiB so it has to split into parts.

Never check the output in: it is large, and *.nessus is gitignored outside
testdata/.
"""
import argparse
import sys

ITEM = (
    '<ReportItem port="{port}" svc_name="{svc}" protocol="tcp" severity="{sev}" pluginID="{pid}" '
    'pluginName="Synthetic Nessus plugin {pid}" pluginFamily="General">\n'
    "<cve>CVE-2026-{pid:05d}</cve>\n<cvss3_base_score>5.3</cvss3_base_score>\n"
    "<description>{desc}</description>\n<fname>synthetic_{pid}.nasl</fname>\n"
    "<plugin_type>remote</plugin_type>\n<risk_factor>Medium</risk_factor>\n"
    "<see_also>https://example.test/{pid}/a\nhttps://example.test/{pid}/b</see_also>\n"
    "<solution>Apply the fixture patch.</solution>\n<synopsis>Synthetic Result {pid}.</synopsis>\n"
    "<plugin_output>{out}</plugin_output>\n</ReportItem>\n"
)
DESC = "Synthetic description text for load testing. " * 12
OUT = "Synthetic plugin output line with &lt;escaped&gt; markup &amp; a reference.\n" * 8


def host_block(i, items, inventory_kb):
    ip = f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}"
    parts = [
        f'<ReportHost name="{ip}"><HostProperties>\n'
        f'<tag name="host-ip">{ip}</tag>\n<tag name="os">linux</tag>\n'
        f'<tag name="HOST_START">Mon Oct 20 10:00:00 2026</tag>\n</HostProperties>\n'
    ]
    for j in range(items):
        pid = 100000 + j
        sev = 0 if j % 10 else 2
        parts.append(ITEM.format(port=1000 + j, svc="www", sev=sev, pid=pid, desc=DESC, out=OUT))
    if inventory_kb:
        line = "  ii  synthetic-package  1.0.0-1  amd64  a synthetic package\n"
        out = line * (inventory_kb * 1024 // len(line))
        parts.append(ITEM.format(port=0, svc="general", sev=0, pid=22869, desc="Inventory.", out=out))
    parts.append("</ReportHost>\n")
    return "".join(parts)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mb", type=float, default=50, help="approximate file size in MB")
    ap.add_argument("--hosts", type=int, default=0, help="number of Hosts (default: from --mb)")
    ap.add_argument("--items", type=int, default=40, help="Results per Host")
    ap.add_argument("--inventory-kb", type=int, default=0, help="KB of inventory output per Host")
    ap.add_argument("--policy-share", type=float, default=0.6, help="share of the file taken by Policy")
    a = ap.parse_args()

    target = int(a.mb * 1024 * 1024)
    per_host = len(host_block(0, a.items, a.inventory_kb).encode())
    report_bytes = target * (1 - a.policy_share)
    hosts = a.hosts or max(1, int(report_bytes / per_host))
    policy_bytes = int(hosts * per_host * a.policy_share / (1 - a.policy_share))

    w = sys.stdout.write
    w('<?xml version="1.0" ?>\n<NessusClientData_v2>\n<Policy><policyName>Synthetic</policyName>\n')
    w("<Preferences><ServerPreferences>\n")
    w("<preference><name>TARGET</name>\n<value>10.0.0.0/8</value>\n</preference>\n")
    w("<preference><name>plugin_set</name>\n<value>")
    w(";".join(str(10000 + n) for n in range(200000)))
    w("</value>\n</preference>\n</ServerPreferences>\n<PluginsPreferences>\n")
    item = (
        "<item><pluginName>Synthetic setting</pluginName>\n<pluginId>{n}</pluginId>\n"
        "<fullName>Synthetic setting {n}[entry]:Value</fullName>\n<preferenceName>Value</preferenceName>\n"
        "<preferenceType>entry</preferenceType>\n<preferenceValues>x</preferenceValues>\n"
        "<selectedValue>x</selectedValue>\n</item>\n"
    )
    written, n = 1_400_000, 0
    while written < policy_bytes:
        s = item.format(n=n)
        w(s)
        written += len(s)
        n += 1
    w('</PluginsPreferences>\n</Preferences>\n</Policy>\n<Report name="Synthetic" xmlns:cm="http://www.nessus.org/cm">\n')
    for i in range(hosts):
        w(host_block(i, a.items, a.inventory_kb))
    w("</Report>\n</NessusClientData_v2>\n")


if __name__ == "__main__":
    main()
