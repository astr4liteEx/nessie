Output docs/demo/extensions.gif
Set Width 1440
Set Height 560
Source docs/demo/common.tape

Hide
Type "export PATH=/tmp/nessie-demo/bin:/usr/bin:/bin; PS1='$ '; set -o pipefail; cd /tmp/nessie-demo; clear"
Enter
Show

Type "nessie services this.nessus"
Sleep 300ms
Enter
Sleep 3.5s
Type "clear"
Enter
Type "nessie filter --cve CVE-2024-6387,CVE-2017-0144 this.nessus | nessie items"
Sleep 300ms
Enter
Sleep 3s
Type "nessie results this.nessus | jq -r '.elements.cve[]?' | sort -u"
Sleep 300ms
Enter
Sleep 4s
Hide
