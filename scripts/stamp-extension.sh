#!/usr/bin/env bash
# stamp-extension.sh <extension> <version>: prints the extension as it ships,
# with extensions/nessie.jq inlined in place of its include and the version
# stamped in, so it is one self-contained file (gah installs executables
# flat, without nessie.jq beside them). Fails if either marker is missing.
set -euo pipefail
src=$1
version=$2
lib="$(dirname "$0")/../extensions/nessie.jq"
if grep -qx 'NESSIE_JQ' "$lib"; then
	echo "stamp-extension.sh: nessie.jq holds the heredoc marker NESSIE_JQ on a line of its own" >&2
	exit 1
fi
out=$(awk -v ver="$version" -v lib="$lib" '
	/^VERSION=0\.0\.0-dev( |$)/ { print "VERSION=" ver; v++; next }
	/^LIB=.include "nessie";.( |$)/ {
		print "LIB=$(cat <<'"'"'NESSIE_JQ'"'"'"
		while ((getline line < lib) > 0) print line
		print "NESSIE_JQ"
		print ")"
		l++
		next
	}
	{ print }
	END { if (v != 1 || l != 1) exit 3 }
' "$src") || {
	echo "stamp-extension.sh: $src lacks the VERSION=0.0.0-dev or LIB='include \"nessie\";' line" >&2
	exit 1
}
printf '%s\n' "$out"
