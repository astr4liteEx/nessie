#!/usr/bin/env bash
# setup.sh rebuilds the scratch data the README demo tapes record against,
# in /tmp/nessie-demo (wiped first, so each recording starts the same). Run
# it from anywhere before each `vhs docs/demo/<name>.tape`. Nothing outside
# /tmp/nessie-demo is touched. Needs cargo, python3 and jq.
#
# The two scans are invented: documentation addresses (192.0.2.0/24),
# example.test names and made-up output. last.nessus is an older scan of the
# same network, so nessie diff has something new, fixed and missing to show.
set -euo pipefail
cd "$(dirname "$0")/../.."

demo=/tmp/nessie-demo
rm -rf "$demo"
mkdir -p "$demo/bin"

cargo build --release -q
cp target/release/nessie "$demo/bin/"
cp extensions/nessie-* extensions/nessie.jq "$demo/bin/"

python3 -I - "$demo" <<'PY'
import sys
from xml.sax.saxutils import escape

demo = sys.argv[1]

# id: (name, family, severity, cves, synopsis)
PLUGINS = {
    19506: ("Nessus Scan Information", "Settings", 0, [], "This plugin displays information about the Nessus scan."),
    11219: ("Nessus SYN scanner", "Port scanners", 0, [], "It is possible to determine which TCP ports are open."),
    22964: ("Service Detection", "Service detection", 0, [], "The remote service could be identified."),
    10107: ("HTTP Server Type and Version", "Web Servers", 0, [], "A web server is running on the remote host."),
    10881: ("SSH Protocol Versions Supported", "General", 0, [], "A SSH server is running on the remote host."),
    57582: ("SSL Self-Signed Certificate", "General", 2, [], "The SSL certificate chain for this service ends in an unrecognized self-signed certificate."),
    51192: ("SSL Certificate Cannot Be Trusted", "General", 2, [], "The SSL certificate for this service cannot be trusted."),
    15901: ("SSL Certificate Expiry", "General", 2, [], "The remote server's SSL certificate has already expired."),
    104743: ("TLS Version 1.0 Protocol Detection", "Service detection", 2, [], "The remote service encrypts traffic using an older version of TLS."),
    42873: ("SSL Medium Strength Cipher Suites Supported (SWEET32)", "General", 3, ["CVE-2016-2183"], "The remote service supports the use of medium strength SSL ciphers."),
    187315: ("SSH Terrapin Prefix Truncation Weakness", "Misc.", 2, ["CVE-2023-48795"], "The remote SSH server is vulnerable to a mitm prefix truncation attack."),
    201194: ("OpenSSH < 9.8 RCE (regreSSHion)", "Misc.", 3, ["CVE-2024-6387"], "The SSH server running on the remote host is affected by a remote code execution vulnerability."),
    97833: ("MS17-010: Security Update for Microsoft Windows SMB Server", "Windows", 4, ["CVE-2017-0143", "CVE-2017-0144"], "The remote Windows host is affected by multiple vulnerabilities."),
    57608: ("SMB Signing not required", "Misc.", 2, [], "Signing is not required on the remote SMB server."),
    18405: ("Remote Desktop Protocol Server Man-in-the-Middle Weakness", "Windows", 2, ["CVE-2005-1794"], "It may be possible to get access to the remote host."),
    10264: ("SNMP Agent Default Community Name (public)", "SNMP", 3, ["CVE-1999-0517"], "The community name of the remote SNMP server can be guessed."),
}
RISK = ["None", "Low", "Medium", "High", "Critical"]

# host: (ip, fqdn, os, [(port, proto, svc, [plugin ids])])
WEB_TLS = [57582, 51192, 104743, 42873]
HOSTS = {
    "web01": ("192.0.2.10", "web01.example.test", "Linux Kernel 5.15 on Ubuntu 22.04",
              [(22, "tcp", "ssh", [11219, 22964, 10881, 187315, 201194]), (80, "tcp", "www", [11219, 10107]),
               (443, "tcp", "www", [11219, 22964, 10107] + WEB_TLS)]),
    "web02": ("192.0.2.11", "web02.example.test", "Linux Kernel 5.15 on Ubuntu 22.04",
              [(22, "tcp", "ssh", [11219, 22964, 10881, 187315, 201194]), (443, "tcp", "www", [11219, 22964, 10107, 57582, 51192])]),
    "mail": ("192.0.2.20", "mail.example.test", "Linux Kernel 6.1 on Debian 12",
             [(25, "tcp", "smtp", [11219, 22964, 15901]), (993, "tcp", "imap", [11219, 22964, 104743])]),
    "files": ("192.0.2.30", "files.example.test", "Microsoft Windows Server 2016",
              [(445, "tcp", "cifs", [11219, 97833, 57608]), (3389, "tcp", "msrdp", [11219, 22964, 18405, 57582])]),
    "dc01": ("192.0.2.31", "dc01.example.test", "Microsoft Windows Server 2019",
             [(389, "tcp", "ldap", [11219, 22964]), (445, "tcp", "cifs", [11219, 57608])]),
    "vpn": ("192.0.2.40", "vpn.example.test", "Linux Kernel 4.19",
            [(443, "tcp", "www", [11219, 22964, 10107, 104743])]),
    "printer": ("192.0.2.50", "printer.example.test", "HP JetDirect",
                [(80, "tcp", "www", [11219, 10107]), (161, "udp", "snmp", [10264])]),
}

def scan(name, hosts, extra=(), drop=()):
    out = ['<?xml version="1.0" ?>\n<NessusClientData_v2>\n<Policy><policyName>External network</policyName>'
           '<Preferences><ServerPreferences><preference><name>TARGET</name><value>192.0.2.0/24</value></preference>'
           '</ServerPreferences></Preferences></Policy>\n',
           f'<Report name="{name}" xmlns:cm="http://www.nessus.org/cm">\n']
    first = True
    for h in hosts:
        ip, fqdn, os_, ports = HOSTS[h]
        out.append(f'<ReportHost name="{ip}"><HostProperties>\n<tag name="host-ip">{ip}</tag>\n'
                   f'<tag name="host-fqdn">{fqdn}</tag>\n<tag name="operating-system">{os_}</tag>\n</HostProperties>\n')
        items = [(p, pr, svc, pid) for p, pr, svc, pids in ports for pid in pids]
        items += [x for x in extra if x[0] == h for x in [x[1:]]]
        if first:
            items.insert(0, (0, "tcp", "general", 19506))
            first = False
        for port, proto, svc, pid in items:
            if (h, port, pid) in drop:
                continue
            pname, fam, sev, cves, syn = PLUGINS[pid]
            o = f"Port {port}/{proto} was found to be open" if pid == 11219 else f"{pname} on {fqdn}:{port}"
            if pid == 19506:
                o = "Information about this scan : \n\nNessus version : 10.8.3\nPlugin feed version : 202611200512\n"
            out.append(f'<ReportItem port="{port}" svc_name="{svc}" protocol="{proto}" severity="{sev}" '
                       f'pluginID="{pid}" pluginName="{escape(pname)}" pluginFamily="{fam}">\n'
                       + "".join(f"<cve>{c}</cve>\n" for c in cves)
                       + f"<risk_factor>{RISK[sev]}</risk_factor>\n<synopsis>{escape(syn)}</synopsis>\n"
                       f"<plugin_output>{escape(o)}</plugin_output>\n</ReportItem>\n")
        out.append("</ReportHost>\n")
    out.append("</Report>\n</NessusClientData_v2>\n")
    return "".join(out)

everyone = list(HOSTS)
# This month: regreSSHion is new on web01 and web02, the printer is gone.
with open(f"{demo}/this.nessus", "w") as f:
    f.write(scan("External network - November", [h for h in everyone if h != "printer"],
                 drop={("vpn", 443, 104743)}))
# Last month: no regreSSHion yet, TLS 1.0 still on the VPN, the printer scanned.
with open(f"{demo}/last.nessus", "w") as f:
    f.write(scan("External network - October", everyone,
                 drop={("web01", 22, 201194), ("web02", 22, 201194)}))
PY

PATH="$demo/bin:$PATH" nessie scan "$demo/last.nessus" "$demo/this.nessus" --json | jq -c '{name, hosts, results: .results.total}'
echo "setup.sh: demo data in $demo"
