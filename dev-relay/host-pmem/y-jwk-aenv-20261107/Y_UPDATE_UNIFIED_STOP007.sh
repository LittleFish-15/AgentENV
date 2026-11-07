#!/usr/bin/env bash
set +x
set -euo pipefail
test "$(id -u)" -eq 0
umask 077
tmp=$(mktemp /tmp/y-stop007.XXXXXXXX.py)
trap 'rm -f -- "$tmp"' EXIT
curl -k -fL --retry 2 --connect-timeout 10 --max-time 120 -H 'Accept: application/vnd.github.raw+json' 'https://api.github.com/repos/LittleFish-15/AgentENV/contents/dev-relay/host-pmem/y-jwk-aenv-20261107/Y_dispatch_stop007.py?ref=1fd751c789a32f595948c13f7fcc26737771d490' -o "$tmp"
printf '%s  %s\n' '8496cfbbe845740a3639a22484af1dd700b30dd211f191ea2cb729f5dfaf350d' "$tmp" | sha256sum -c -
/usr/bin/python3 -I -B - "$tmp" <<'INSTALL_STOP007'
ENTRY_PIN='d374232a4c63cb37e2c66138b953989fb8529b386540d9fd650f5793a1fd90a6'
DISPATCH_PIN='8496cfbbe845740a3639a22484af1dd700b30dd211f191ea2cb729f5dfaf350d'
OLD_HEX='23212f62696e2f626173680a736574202d65750a756d61736b203037370a65786563202f7573722f62696e2f707974686f6e33202d49202d42202f686f6d652f6a776b2f792d61656e762d636f6e74726f6c2f72656c61792f656e7472792e70790a'
NEW_HEX='23212f62696e2f626173680a736574202d65750a756d61736b203037370a65786563202f7573722f62696e2f707974686f6e33202d49202d42202f686f6d652f6a776b2f792d61656e762d636f6e74726f6c2f72656c61792f64697370617463682d73746f703030372e70790a'
import hashlib,os,pathlib,sys
P=pathlib.Path
root=P('/home/jwk/y-aenv-control');state=root/'relay'
assert os.geteuid()==0 and root.resolve()==root and root.stat().st_uid==0
assert state.resolve()==state and state.stat().st_uid==0
assert hashlib.sha256((state/'entry.py').read_bytes()).hexdigest()==ENTRY_PIN
raw=P(sys.argv[1]).read_bytes();assert hashlib.sha256(raw).hexdigest()==DISPATCH_PIN
target=state/'dispatch-stop007.py';current=root/'root-start.sh'
assert not target.is_symlink() and not current.is_symlink() and current.stat().st_uid==0
old=bytes.fromhex(OLD_HEX);new=bytes.fromhex(NEW_HEX)
assert current.read_bytes() in (old,new),'Unknown unified wrapper preserved'
def write(path,data,mode):
 assert not path.is_symlink()
 temp=path.with_name(path.name+'.stop007-next')
 fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
 with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
 os.replace(temp,path)
backup=root/'root-start.before-stop007.sh'
if not backup.exists():write(backup,old,0o700)
else:assert backup.read_bytes()==old
if target.exists():assert target.stat().st_uid==0 and target.read_bytes()==raw
else:write(target,raw,0o600)
if current.read_bytes()!=new:write(current,new,0o700)
print('UNIFIED_ENTRY_STOP_SUPPORT_INSTALLED',flush=True)

INSTALL_STOP007
exec bash /home/jwk/y-aenv-control/root-start.sh
