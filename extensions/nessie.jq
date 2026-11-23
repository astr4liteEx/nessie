# Shared by nessie's starter extensions. Run with: jq -nrR -L <dir> 'include "nessie"; ...'
#
# Lines are read raw and parsed here, so a record can be printed as the
# line it arrived as: jq -c would rewrite its escapes ("é" as "é"),
# and records nessie passes on must come out byte for byte.

# lines($name; f): f runs on {raw, rec, line} for each JSON object on the
# input and emits the lines to print. Blank lines are skipped; any other
# line is reported on stderr as "<name>: -:<line>: not a JSON object", and
# the run exits 1 once the input is read.
def lines($name; f):
  foreach ((inputs | {raw: ., line: input_line_number}), {end: true}) as $in ({bad: 0};
    .emit = null | .msg = null
    | if $in.end then .end = true
      elif ($in.raw | test("^\\s*$")) then .
      else (try ($in.raw | fromjson) catch null) as $rec
        | if ($rec | type) == "object" then .emit = ($in + {rec: $rec})
          else .bad += 1 | .msg = "\($name): -:\($in.line): not a JSON object\n" end
      end;
    if .end then (if .bad > 0 then "" | halt_error(1) else empty end)
    elif .msg then (.msg | stderr | empty)
    elif .emit then (.emit | f)
    else empty end
  );

# A Host as one name: fqdn, else ip, else name (empty values skipped).
def host_label: [.fqdn, .ip, .name] | map(select(. != null and . != "")) | first // "";

# An IPv4 address as a number, or null.
def ipv4: if type == "string" and test("^\\d{1,3}(\\.\\d{1,3}){3}$")
  then split(".") | map(tonumber) | if all(. < 256) then .[0] * 16777216 + .[1] * 65536 + .[2] * 256 + .[3] else null end
  else null end;

# True when the IPv4 address $ip is inside $cidr ("a.b.c.d/n").
def in_cidr($ip; $cidr):
  ($cidr | split("/")) as [$net, $bits]
  | ($bits | tonumber) as $b
  | pow(2; 32 - $b) as $size
  | ($ip | ipv4) as $i | ($net | ipv4) as $n
  | $i != null and $n != null and (($i / $size) | floor) == (($n / $size) | floor);

# A Host matches a --host value: equal to its name, ip or fqdn (fqdn
# ignoring case and a trailing dot), or for a CIDR, its ip inside it.
def host_is($v):
  if ($v | contains("/")) then in_cidr(.ip // .name; $v)
  else .name == $v or .ip == $v
    or (((.fqdn // "") | ascii_downcase | rtrimstr(".")) == ($v | ascii_downcase | rtrimstr(".")) and $v != "")
  end;

# filter's test. $c holds the flags, each a list (OR within a list); the
# flags given must all match (AND across flags).
def matches($c):
  . as $r
  | ($c.plugin_id | length == 0 or any(.[]; . == $r.plugin_id))
  and ($c.family | length == 0 or any(.[]; ascii_downcase == ($r.plugin_family | ascii_downcase)))
  and ($c.host | length == 0 or any(.[]; . as $h | $r.host | host_is($h)))
  and ($c.port | length == 0 or any(.[]; . == $r.port))
  and ($c.protocol | length == 0 or any(.[]; ascii_downcase == $r.protocol))
  and ($c.cve | length == 0 or any(.[] | ascii_upcase; . as $v | any(($r.elements.cve // [])[]; ascii_upcase == $v)))
  and ($c.min_severity == null or $r.severity >= $c.min_severity)
  and ($c.max_severity == null or $r.severity <= $c.max_severity)
  and ($c.exploit_available | not or (($r.elements.exploit_available // [])[0] == "true"));

# search's test: $re (Oniguruma, with $flags) against the members named in
# $in, or by default plugin_name, every elements value and plugin_output.
# A name in $in is plugin_name, plugin_output, svc_name or an element.
def found($re; $flags; $in):
  . as $r
  | if ($in | length) == 0
    then [$r.plugin_name, ($r.elements | .[] | .[]), $r.plugin_output]
    else [$in[] as $m | if ($m | IN("plugin_name", "plugin_output", "svc_name")) then $r[$m] else ($r.elements[$m] // [])[] end]
    end
  | any(.[] | select(type == "string"); test($re; $flags));
