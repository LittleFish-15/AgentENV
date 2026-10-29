#!/bin/bash
# Scope: create/check jwk and its own workspace. No sudo grants or services.
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
if [ "$#" -ne 4 ]; then
    echo 'Usage: bash bootstrap_account.sh plan|apply node-c|node-d --machine-id EXACT_ID'
    exit 2
fi
action=$1
role=$2
test "$3" = --machine-id
expected_id=$4
case "$action" in plan|apply) ;; *) exit 2 ;; esac
case "$role" in node-c|node-d) ;; *) exit 2 ;; esac
test "$(id -u)" -eq 0
test -n "$expected_id"
test "$(cat /etc/machine-id)" = "$expected_id"
test -x /bin/bash
if getent passwd jwk >/dev/null; then
    test "$(id -u jwk)" -eq 1204
    test "$(id -g jwk)" -eq 1205
    test "$(getent passwd jwk | cut -d: -f6)" = /home/jwk
    test "$(getent passwd jwk | cut -d: -f7)" = /bin/bash
elif getent passwd 1204 >/dev/null; then
    echo 'STOP_UID_1204_OCCUPIED; do not renumber existing accounts'
    exit 1
fi
if getent group jwk >/dev/null; then
    test "$(getent group jwk | cut -d: -f3)" -eq 1205
elif getent group 1205 >/dev/null; then
    echo 'STOP_GID_1205_OCCUPIED; do not renumber existing groups'
    exit 1
fi
for folder in /home/jwk /home/jwk/agent; do
    if [ -e "$folder" ] || [ -L "$folder" ]; then
        test ! -L "$folder"
        test -d "$folder"
        test "$(stat -c %u "$folder")" -eq 1204
        test "$(stat -c %g "$folder")" -eq 1205
        test "$(readlink -f "$folder")" = "$folder"
        # Existing workspace permissions are checked, never silently relaxed.
        mode=$(stat -c %a "$folder")
        test $((8#$mode & 0022)) -eq 0
    fi
done
if ! getent passwd jwk >/dev/null && [ -e /home/jwk ]; then
    echo 'STOP_EXISTING_HOME_WITHOUT_MATCHING_ACCOUNT'
    exit 1
fi
echo "ACCOUNT_PLAN role=$role uid=1204 gid=1205 home=/home/jwk workspace=/home/jwk/agent"
if [ "$action" = plan ]; then
    echo ACCOUNT_PLAN_ONLY_NO_CHANGES
    exit 0
fi
if ! getent group jwk >/dev/null; then groupadd --gid 1205 jwk; fi
if ! getent passwd jwk >/dev/null; then
    useradd --create-home --uid 1204 --gid 1205 --shell /bin/bash --home-dir /home/jwk jwk
fi
if [ ! -d /home/jwk/agent ]; then
    install -d -m 0700 -o 1204 -g 1205 /home/jwk/agent
fi
test "$(id -u jwk)" -eq 1204
test "$(id -g jwk)" -eq 1205
echo ACCOUNT_WORKSPACE_READY_PASSWORD_NOT_SET_BY_SCRIPT
echo 'Set the requested password using trusted interactive passwd jwk; never put it in a command or log.'
