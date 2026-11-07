#!/usr/bin/env bash
set +x
set -euo pipefail
test "$(id -u)" -eq 0
umask 077
tmp=$(mktemp /tmp/y-reconcile005.XXXXXXXX.py)
trap 'rm -f -- "$tmp"' EXIT
curl -k -fL --retry 2 --connect-timeout 10 --max-time 120 -H 'Accept: application/vnd.github.raw+json' 'https://api.github.com/repos/LittleFish-15/AgentENV/contents/dev-relay/host-pmem/y-jwk-aenv-20261107/Y_reconcile005.template.py?ref=386f1db13bd0781867f12f2c0362a90573007385' -o "$tmp"
printf '%s  %s\n' 'd4ac452c9c393e5aea01de2276a8d36d987b8ef28faf36856375ce79780bea1c' "$tmp" | sha256sum -c -
/usr/bin/python3 -I -B "$tmp"
