#!/usr/bin/env bash
set +x
set -euo pipefail
test "$(id -u)" -eq 0
umask 077
tmp=$(mktemp /tmp/y-identity005.XXXXXXXX.py)
trap 'rm -f -- "$tmp"' EXIT
curl -k -fL --retry 2 --connect-timeout 10 --max-time 120 -H 'Accept: application/vnd.github.raw+json' 'https://api.github.com/repos/LittleFish-15/AgentENV/contents/dev-relay/host-pmem/y-restored-readonly-20261109/Y_unified_identity005.py?ref=0ee9fe3a8f4afde1b0871668c0ee1a50ecef15f1' -o "$tmp"
printf '%s  %s\n' '77cb24d10dda2ab78568ec5e8c894faa730c9c899b0c0ba70b77de0e3d091bd9' "$tmp" | sha256sum -c -
/usr/bin/python3 -I -B - "$tmp" <<'INSTALL_IDENTITY005'
ENTRY_PIN='0a9012252418249dd44c034db362294bff1c5070412d1887a5e3020634794897'
SOURCE_PIN='77cb24d10dda2ab78568ec5e8c894faa730c9c899b0c0ba70b77de0e3d091bd9'
OLD='23212f62696e2f626173680a736574202d65750a756d61736b203037370a65786563202f7573722f62696e2f707974686f6e33202d49202d42202f686f6d652f6a776b2f792d61656e762d636f6e74726f6c2f72656c61792d726573746f7265642d32303236313130392f656e7472792e70790a'
NEW='23212f62696e2f626173680a736574202d65750a756d61736b203037370a65786563202f7573722f62696e2f707974686f6e33202d49202d42202f686f6d652f6a776b2f792d61656e762d636f6e74726f6c2f72656c61792d726573746f7265642d32303236313130392f6964656e746974793030352e70790a'
import hashlib,os,pathlib,sys
P=pathlib.Path;r=P('/home/jwk/y-aenv-control');s=r/'relay-restored-20261109'
assert os.geteuid()==0 and r.resolve()==r and s.resolve()==s and r.stat().st_uid==0 and s.stat().st_uid==0
assert hashlib.sha256((s/'entry.py').read_bytes()).hexdigest()==ENTRY_PIN
raw=P(sys.argv[1]).read_bytes();assert hashlib.sha256(raw).hexdigest()==SOURCE_PIN
wrapper=r/'root-start.sh';assert not wrapper.is_symlink() and wrapper.stat().st_uid==0
old=bytes.fromhex(OLD);new=bytes.fromhex(NEW)
assert wrapper.read_bytes() in (old,new),'Unknown entry preserved'
def save(path,data,mode):
 assert not path.is_symlink()
 tmp=path.with_name(path.name+'.identity005-next')
 fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
 with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
 os.replace(tmp,path)
target=s/'identity005.py'
if target.exists():assert target.stat().st_uid==0 and target.read_bytes()==raw
else:save(target,raw,0o600)
backup=r/'root-start.before-identity005.sh'
if not backup.exists():save(backup,old,0o700)
else:assert backup.read_bytes()==old
if wrapper.read_bytes()!=new:save(wrapper,new,0o700)

INSTALL_IDENTITY005
exec bash /home/jwk/y-aenv-control/root-start.sh
