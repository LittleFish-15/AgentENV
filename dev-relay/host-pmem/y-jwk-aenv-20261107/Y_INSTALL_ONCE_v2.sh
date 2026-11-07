#!/usr/bin/env bash
set +x
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then echo "Use a root terminal to install Y entry" >&2; exit 1; fi
umask 077
tmp=$(mktemp /tmp/y-aenv-entry-v2.XXXXXXXX.py)
trap 'rm -f -- "$tmp"' EXIT
curl -k -fL --retry 2 --connect-timeout 10 --max-time 120 --max-filesize 131072 -H 'Accept: application/vnd.github.raw+json' 'https://api.github.com/repos/LittleFish-15/AgentENV/contents/dev-relay/host-pmem/y-jwk-aenv-20261107/Y_root_entry_v2.py?ref=bbc204361a6d06aa645d66a619b671e6218d9225' -o "$tmp"
printf '%s  %s\n' 'd374232a4c63cb37e2c66138b953989fb8529b386540d9fd650f5793a1fd90a6' "$tmp" | sha256sum -c -
test "$(wc -c < "$tmp")" -eq 28713
/usr/bin/python3 -I -B "$tmp" --install-run
