"""Prepare the owner source image or reconcile the named importer export."""

import argparse
import base64
import hashlib
import json
import os
import shutil
import stat
import subprocess
import uuid
from pathlib import Path


SERVER_SHA = '1d450f7cabbd10c41ef11bd6dc093e962b2439204a5a376e1bb2c748210ca917'
PACK_SHA = '9dfc1386dc989e36ecba9f74cbabe4c5d1983a800a2b2cceaf9677246a580e39'
LOWER_SHA = '42d2db6070a949f224fc2df0219d0bba969488dc57d1dba84aa39b45e65e4799'
IMAGE_ROOT = Path('/root/aenv-pmem')
SERVERS = (Path('/opt/aenv/bin/server'),
           Path('/home/jwk/agent/sp3-mn/src/AgentENV/target/release/server'))
PACK = 'c2V0IC1ldW8gcGlwZWZhaWwKdW1hc2sgMDc3CiMgQXJndW1lbnRzIG11c3QgYmUgYW4gZXhpc3RpbmcgbG93ZXIgZmlsZSwgaXRzIGFzc2lnbmVkIGRpcmVjdC1jaGlsZCBuYW1lLCBpdHMKIyByZWNvcmRlZCBiYXJlIFNIQS0yNTYsIGFuZCB0aGUgYWJzb2x1dGUgcGF0aCB0byB0aGUgZXhpc3Rpbmcgc2VydmVyIGJpbmFyeS4KbG93ZXI9JDEKbmFtZT0kMgpleHBlY3RlZD0kMwpzZXJ2ZXI9JDQKW1sgJChpZCAtdSkgPSAwICYmICQoaG9zdG5hbWUgLXMpID0gYWdlbnQxICYmICQoZ2V0Y29uZiBQQUdFU0laRSkgPSA0MDk2IF1dCltbICRsb3dlciA9IC8qICYmICRzZXJ2ZXIgPSAvKiAmJiAtZiAkbG93ZXIgJiYgISAtTCAkbG93ZXIgJiYgLXggJHNlcnZlciBdXQpbWyAkbmFtZSA9fiBeW0EtWmEtejAtOV1bQS1aYS16MC05Ll8tXSokICYmICRleHBlY3RlZCA9fiBeW2EtZjAtOV17NjR9JCBdXQpwYXJlbnQ9L3Jvb3QvYWVudi1wbWVtCltbIC1kICRwYXJlbnQgJiYgJChyZWFscGF0aCAtZSAtLSAiJHBhcmVudCIpID0gIiRwYXJlbnQiIF1dCnByaW50ZiAnJXMgICVzXG4nICIkZXhwZWN0ZWQiICIkbG93ZXIiIHwgc2hhMjU2c3VtIC1jIC0KYnl0ZXM9JChzdGF0IC1jICVzIC0tICIkbG93ZXIiKQpbWyAkYnl0ZXMgLWd0IDAgJiYgJGJ5dGVzIC1sZSA5Mzk1MjQwOTYgXV0Kd29yaz0kKG1rdGVtcCAtZCAiJHBhcmVudC9sb3dlci1wYWNrLVhYWFhYWFhYIikKb3V0ZXI9JHdvcmsvbG93ZXJzLmV4dDQKdmlldz0kd29yay92aWV3Cm1rZGlyIC1tIDA3MDAgIiR2aWV3IgooIHNldCAtbyBub2Nsb2JiZXI7IDogPiAiJG91dGVyIiApCnRydW5jYXRlIC1zIDFHIC0tICIkb3V0ZXIiCm1rZTJmcyAtcSAtRiAtdCBleHQ0IC1iIDQwOTYgLW0gMCAtTyAnXmhhc19qb3VybmFsLF5pbmxpbmVfZGF0YScgXAogIC1FIGxhenlfaXRhYmxlX2luaXQ9MCxsYXp5X2pvdXJuYWxfaW5pdD0wICIkb3V0ZXIiCnVuc2hhcmUgLS1tb3VudCAtLXByb3BhZ2F0aW9uIHByaXZhdGUgL2Jpbi9iYXNoIC1zIC0tICIkb3V0ZXIiICIkdmlldyIgIiRsb3dlciIgIiRuYW1lIiAiJGV4cGVjdGVkIiAiJGJ5dGVzIiA8PCdQQUNLJwpzZXQgLWV1byBwaXBlZmFpbApvdXRlcj0kMSB2aWV3PSQyIGxvd2VyPSQzIG5hbWU9JDQgZXhwZWN0ZWQ9JDUgYnl0ZXM9JDYKbW91bnQgLXQgZXh0NCAtbyBsb29wLG5vc3VpZCxub2Rldixub2V4ZWMgLS0gIiRvdXRlciIgIiR2aWV3Igp0cmFwICd1bW91bnQgLS0gIiR2aWV3IicgRVhJVAp0YXJnZXQ9JHZpZXcvJG5hbWUKKCBzZXQgLW8gbm9jbG9iYmVyOyA6ID4gIiR0YXJnZXQiICkKZGQgaWY9IiRsb3dlciIgb2Y9IiR0YXJnZXQiIGJzPTRNIGNvbnY9ZnN5bmMgc3RhdHVzPW5vbmUKdGVzdCAiJChzdGF0IC1jICVzIC0tICIkdGFyZ2V0IikiIC1lcSAiJGJ5dGVzIgpwcmludGYgJyVzICAlc1xuJyAiJGV4cGVjdGVkIiAiJHRhcmdldCIgfCBzaGEyNTZzdW0gLWMgLQovdXNyL2Jpbi9weXRob24zIC1JIC1CIC0gIiR0YXJnZXQiICIkYnl0ZXMiICIkKHN0YXQgLWMgJXMgLS0gIiRvdXRlciIpIiA8PCdGSUVNQVAnCmltcG9ydCBmY250bAppbXBvcnQgb3MKaW1wb3J0IHN0cnVjdAppbXBvcnQgc3lzCgpwYXRoLCBsZW5ndGgsIGNhcGFjaXR5ID0gc3lzLmFyZ3ZbMV0sIGludChzeXMuYXJndlsyXSksIGludChzeXMuYXJndlszXSkKcGFnZSA9IG9zLnN5c2NvbmYoJ1NDX1BBR0VTSVpFJykKaGVhZGVyID0gc3RydWN0LlN0cnVjdCgnPFFRSUlJSScpCmV4dGVudCA9IHN0cnVjdC5TdHJ1Y3QoJzxRUVFRUUlJSUknKQpsaW1pdCA9IDEyOAp3aXJlID0gYnl0ZWFycmF5KGhlYWRlci5zaXplICsgbGltaXQgKiBleHRlbnQuc2l6ZSkKaGVhZGVyLnBhY2tfaW50byh3aXJlLCAwLCAwLCBsZW5ndGgsIDAsIDAsIGxpbWl0LCAwKQp3aXRoIG9wZW4ocGF0aCwgJ3JiJykgYXMgbG93ZXI6CiAgICBmY250bC5pb2N0bChsb3dlci5maWxlbm8oKSwgMHhjMDIwNjYwYiwgd2lyZSwgVHJ1ZSkKc3RhcnQsIHNwYW4sIGZsYWdzLCBtYXBwZWQsIGNvdW50LCB6ZXJvID0gaGVhZGVyLnVucGFja19mcm9tKHdpcmUpCmlmIChzdGFydCwgc3BhbiwgZmxhZ3MsIGNvdW50LCB6ZXJvKSAhPSAoMCwgbGVuZ3RoLCAwLCBsaW1pdCwgMCkgb3Igbm90IDEgPD0gbWFwcGVkIDw9IGxpbWl0OgogICAgc3lzLmV4aXQoJ0luY29tcGxldGUgRklFTUFQIHJlc3VsdCcpCm5leHRfb2Zmc2V0LCByYW5nZXMgPSAwLCBbXQpmb3IgaW5kZXggaW4gcmFuZ2UobWFwcGVkKToKICAgIGxvZ2ljYWwsIHBoeXNpY2FsLCBzaXplLCB6MCwgejEsIGZsYWdzLCB6MiwgejMsIHo0ID0gZXh0ZW50LnVucGFja19mcm9tKAogICAgICAgIHdpcmUsIGhlYWRlci5zaXplICsgaW5kZXggKiBleHRlbnQuc2l6ZSkKICAgIGlmIChsb2dpY2FsICE9IG5leHRfb2Zmc2V0IG9yIG5vdCBsb2dpY2FsIDwgbGVuZ3RoIG9yIG5vdCBzaXplIG9yCiAgICAgICAgICAgIChsb2dpY2FsIHwgcGh5c2ljYWwgfCBzaXplKSAlIHBhZ2Ugb3IgcGh5c2ljYWwgKyBzaXplID4gY2FwYWNpdHkgb3IKICAgICAgICAgICAgYW55KCh6MCwgejEsIHoyLCB6MywgejQpKSBvciBmbGFncyAmIH4weDEwMDEgb3IKICAgICAgICAgICAgYm9vbChmbGFncyAmIDEpICE9IChpbmRleCA9PSBtYXBwZWQgLSAxKSk6CiAgICAgICAgc3lzLmV4aXQoJ0xvd2VyIGhhcyBhIGdhcCwgdW53cml0dGVuL3VuYWxpZ25lZCBleHRlbnQgb3IgdW5zdXBwb3J0ZWQgRklFTUFQIGZsYWcnKQogICAgbmV4dF9vZmZzZXQgKz0gc2l6ZQogICAgcmFuZ2VzLmFwcGVuZCgocGh5c2ljYWwsIHBoeXNpY2FsICsgc2l6ZSkpCnJhbmdlcy5zb3J0KCkKaWYgbmV4dF9vZmZzZXQgPCBsZW5ndGggb3IgYW55KGFbMV0gPiBiWzBdIGZvciBhLCBiIGluIHppcChyYW5nZXMsIHJhbmdlc1sxOl0pKToKICAgIHN5cy5leGl0KCdGSUVNQVAgZG9lcyBub3QgY292ZXIgdGhlIGxvd2VyIG9yIHBoeXNpY2FsIGV4dGVudHMgb3ZlcmxhcCcpCnByaW50KGYnRklFTUFQIHByZWZsaWdodCBPSzoge21hcHBlZH0gZXh0ZW50cywge2xlbmd0aH0gbG93ZXIgYnl0ZXMnKQpGSUVNQVAKaWYgY29tbWFuZCAtdiBmaWxlZnJhZyA+L2Rldi9udWxsOyB0aGVuCiAgZmlsZWZyYWcgLXYgLWI0MDk2ICIkdGFyZ2V0IiB8IHRlZSAiJChkaXJuYW1lIC0tICIkb3V0ZXIiKS9sb3dlci5maWxlZnJhZyIKZmkKdW1vdW50IC0tICIkdmlldyIKdHJhcCAtIEVYSVQKUEFDSwplMmZzY2sgLWZuICIkb3V0ZXIiCm91dGVyX3NoYT0kKHNoYTI1NnN1bSAtLSAiJG91dGVyIiB8IGN1dCAtZCAnICcgLWYgMSkKIiRzZXJ2ZXIiIC0tcHJlcGFyZS1ob3N0LXBtZW0taW1hZ2UgIiRvdXRlciIgLS1ob3N0LXBtZW0taW1hZ2Utc2hhMjU2ICIkb3V0ZXJfc2hhIiBcCiAgLS1ob3N0LXBtZW0tbWFuaWZlc3QgIiR3b3JrL21hbmlmZXN0Lmpzb24iCnByaW50ZiAnc291cmNlSW1hZ2U9JXNcbm91dGVyU0hBPSVzXG5tYW5pZmVzdD0lc1xubG93ZXIubmFtZT0lc1xubG93ZXIuYnl0ZXM9JXNcbmxvd2VyLmRpZ2VzdD1zaGEyNTY6JXNcbicgXAogICIkb3V0ZXIiICIkb3V0ZXJfc2hhIiAiJHdvcmsvbWFuaWZlc3QuanNvbiIgIiRuYW1lIiAiJGJ5dGVzIiAiJGV4cGVjdGVkIgo='


def sha256(path):
    with path.open('rb') as stream:
        digest = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def prepare_owner():
    payload = base64.b64decode(PACK, validate=True)
    if hashlib.sha256(payload).hexdigest() != PACK_SHA:
        raise RuntimeError('Embedded outer-image script digest differs')
    server = next((path for path in SERVERS if path.is_file() and sha256(path) == SERVER_SHA), None)
    if server is None:
        raise RuntimeError('Previously verified server binary was not found at its two known paths')
    if shutil.disk_usage(IMAGE_ROOT).free < (1 << 30) + (64 << 20):
        raise RuntimeError('Not enough space for the new 1 GiB private image')
    lower = IMAGE_ROOT / 'aenv-template.ext4'
    if lower.stat().st_size != 536870912:
        raise RuntimeError('Expected original 512 MiB inner fixture')
    print('MN_OWNER_IMAGE_PREPARE=' + str(server), flush=True)
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LANG': 'C', 'LC_ALL': 'C'}
    return subprocess.run(['/bin/bash', '-s', '--', str(lower), lower.name, LOWER_SHA, str(server)],
                          input=payload, env=env).returncode


def read_region(path, name):
    try:
        return (path / name).read_text().strip()
    except FileNotFoundError:
        return None


def importer_status(run, pool):
    matches, unreadable = [], 0
    sysfs = Path('/sys/devices/obmm')
    paths = sorted(sysfs.glob('obmm_shmdev*'))
    for region in paths[:256]:
        try:
            with (region / 'priv').open('rb') as stream:
                raw = stream.read(512)
            if raw[152:204].split(b'\x00', 1)[0] == ('aenv_' + pool.hex).encode('ascii'):
                path = Path('/dev') / region.name
                info = path.stat()
                if not stat.S_ISCHR(info.st_mode):
                    raise ValueError('Expected a character device')
                matches.append({'path': str(path), 'rdev': info.st_rdev, 'type': read_region(region, 'type'),
                                'size': read_region(region, 'size'), 'privLen': read_region(region, 'priv_len')})
        except (OSError, ValueError):
            unreadable += 1

    references, still_running, errors = [], [], 0
    devices = {item['rdev'] for item in matches}
    device_paths = {item['path'] for item in matches}
    for process in Path('/proc').iterdir():
        if not process.name.isdecimal():
            continue
        try:
            exe = os.readlink(process / 'exe')
            if Path(exe).name.startswith('agentenv-ub-provider'):
                still_running.append({'pid': process.name, 'exe': exe})
        except OSError:
            pass
        if not devices:
            continue
        try:
            fd_refs = []
            for fd in (process / 'fd').iterdir():
                try:
                    info = fd.stat()
                except FileNotFoundError:
                    continue
                if stat.S_ISCHR(info.st_mode) and info.st_rdev in devices:
                    fd_refs.append(fd.name)
            with (process / 'maps').open('r', errors='replace') as maps:
                mapping_refs = [line.split(None, 1)[0] for line in maps
                                if any(line.rstrip().endswith((path, path + ' (deleted)'))
                                       for path in device_paths)]
            if fd_refs or mapping_refs:
                references.append({'pid': process.name, 'fds': fd_refs, 'maps': mapping_refs})
        except (FileNotFoundError, ProcessLookupError):
            pass
        except OSError:
            errors += 1

    journal_path = Path('/var/lib/aenv-ub-sdk') / ('run-' + run.hex) / 'state/sdk.json'
    journal = json.loads(journal_path.read_text())
    if journal.get('run') != run.hex or journal.get('node') != 'agent2':
        raise RuntimeError('SDK journal identity differs')
    pool_record = journal['pools'].get(str(pool), {})
    print(json.dumps({'status': 'MN_IMPORTER_RECONCILIATION_READONLY', 'run': run.hex,
                      'object': 'aenv_' + pool.hex, 'matches': matches, 'unreadableRegions': unreadable,
                      'sysfsPresent': sysfs.is_dir(), 'truncatedRegions': len(paths) > 256,
                      'references': references, 'runningProviders': still_running,
                      'unreadableProcessRefs': errors, 'poolPhase': pool_record.get('phase'),
                      'allocationOwner': pool_record.get('allocationOwner'),
                      'sdkFinalized': journal.get('finalizeAcknowledged')}), flush=True)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('owner-image', 'importer-check'))
    parser.add_argument('--run', type=uuid.UUID)
    parser.add_argument('--pool', type=uuid.UUID)
    args = parser.parse_args()
    host = os.uname().nodename.split('.')[0]
    if os.geteuid() != 0:
        raise RuntimeError('Use the unified root entry')
    if args.mode == 'owner-image' and host == 'agent1' and args.run is None and args.pool is None:
        return prepare_owner()
    if args.mode == 'importer-check' and host == 'agent2' and args.run is not None and args.pool is not None:
        return importer_status(args.run, args.pool)
    raise RuntimeError('Worker role does not match the node or parameters')


if __name__ == '__main__':
    raise SystemExit(main())
