#!/usr/bin/env bash
set +x
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then echo "Run this installer with sudo bash" >&2; exit 1; fi
umask 077
tmp=$(mktemp /tmp/y-aenv-entry.XXXXXXXX.py)
trap 'rm -f -- "$tmp"' EXIT
curl -fL --retry 2 --connect-timeout 10 --max-time 120 --max-filesize 131072 -H 'Accept: application/vnd.github.raw+json' 'https://api.github.com/repos/LittleFish-15/AgentENV/contents/dev-relay/host-pmem/y-jwk-aenv-20261107/Y_root_entry_v1.py?ref=ec132e132a358b07fd46b87b9a894ea8e6496423' -o "$tmp"
printf '%s  %s\n' '5f20eb50d9f622c9d3a5ea3ecf5b2fa1f97bd7ec1e7ef9d973824db5c64fa10c' "$tmp" | sha256sum -c -
test "$(wc -c < "$tmp")" -eq 27859
/usr/bin/python3 -I -B "$tmp" --install-run
