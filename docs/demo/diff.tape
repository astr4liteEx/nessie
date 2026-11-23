Output docs/demo/diff.gif
Set Width 1440
Set Height 620
Source docs/demo/common.tape

Hide
Type "export PATH=/tmp/nessie-demo/bin:/usr/bin:/bin; PS1='$ '; set -o pipefail; cd /tmp/nessie-demo; clear"
Enter
Show

Type "nessie diff --min-severity 3 last.nessus this.nessus"
Sleep 300ms
Enter
Sleep 4s
Type `nessie diff last.nessus this.nessus | jq -c 'select(.diff.state != "present")' | nessie table`
Sleep 300ms
Enter
Sleep 4.5s
Hide
