# Shared settings for the README demo tapes. Run docs/demo/setup.sh first;
# tapes are run from the repo root: vhs docs/demo/<name>.tape
#
# Each tape sets PATH to /tmp/nessie-demo/bin:/usr/bin:/bin in its hidden
# setup, so only the demo's nessie and extensions show up (Env PATH would
# also hide ttyd from vhs). Each tape sets its own Width and Height before
# sourcing this file, since vhs ignores a Set once other commands ran.
Require jq

Set Shell "bash"
Set FontFamily "JetBrainsMono Nerd Font Mono"
Set FontSize 18
Set Padding 24
Set TypingSpeed 45ms
Set Theme "Catppuccin Mocha"

Env COLORTERM "truecolor"
