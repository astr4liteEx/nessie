# install.sh [--prefix DIR] [--rpt]: installs nessie and its starter
# extensions from this release folder. Run it with sh: sh install.sh
#
#   --prefix DIR   install into DIR/bin (default: ~/.local, so ~/.local/bin)
#   --rpt          also link rpt-nessus to nessie, so rpt runs it as a plugin
set -eu

prefix=${HOME:?}/.local
rpt=0
while [ $# -gt 0 ]; do
	case $1 in
	--prefix) [ $# -ge 2 ] || { echo "install.sh: --prefix needs a folder" >&2; exit 2; }; prefix=$2; shift 2 ;;
	--prefix=*) prefix=${1#*=}; shift ;;
	--rpt) rpt=1; shift ;;
	-h | --help) sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) echo "install.sh: unknown argument $1 (see sh install.sh --help)" >&2; exit 2 ;;
	esac
done

here=$(cd "$(dirname "$0")" && pwd)
[ -x "$here/bin/nessie" ] || { echo "install.sh: run it from the unpacked release folder (no bin/nessie beside it)" >&2; exit 1; }
mkdir -p "$prefix/bin"
for f in "$here"/bin/*; do
	cp "$f" "$prefix/bin/"
	chmod 755 "$prefix/bin/$(basename "$f")"
	echo "installed $prefix/bin/$(basename "$f")"
done
if [ "$rpt" = 1 ]; then
	ln -sf nessie "$prefix/bin/rpt-nessus"
	echo "linked $prefix/bin/rpt-nessus -> nessie"
fi
case ":$PATH:" in
*":$prefix/bin:"*) ;;
*) echo "note: $prefix/bin is not on PATH; add it to run nessie by name" ;;
esac
command -v jq >/dev/null 2>&1 || echo "note: the starter extensions need jq 1.7 or later, and there is no jq on PATH"
