#!/usr/bin/env bash
set +x
set -euo pipefail
test "$(id -u)" -eq 0
umask 077
tmp=$(mktemp /tmp/y-restored-readonly.XXXXXXXX.py)
trap 'rm -f -- "$tmp"' EXIT
curl -k -fL --retry 2 --connect-timeout 10 --max-time 120 -H 'Accept: application/vnd.github.raw+json' 'https://api.github.com/repos/LittleFish-15/AgentENV/contents/dev-relay/host-pmem/y-restored-readonly-20261109/Y_restored_readonly_entry_v1.py?ref=42d8704fbec4bd5d33e23a4d4bc64bbcc066d4ec' -o "$tmp"
printf '%s  %s\n' '0a9012252418249dd44c034db362294bff1c5070412d1887a5e3020634794897' "$tmp" | sha256sum -c -
test "$(wc -c < "$tmp")" -eq 29234
/usr/bin/python3 -I -B "$tmp" --install-run
