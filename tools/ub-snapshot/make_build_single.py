"""Generate one text .py containing committed changes, reusing the target's baseline."""
import argparse
import ast
from pathlib import Path
import pprint
import subprocess

DIRECTORY = Path(__file__).resolve().parent
BASE = 'ae9c62693839ce7effa2b45df31c0039ae4f9fbc'


def git(*args):
    return subprocess.check_output(['git', *args], cwd=DIRECTORY)


def files_at(commit):
    result = {}
    for row in git('ls-tree', '-r', '-l', '-z', '--full-tree', commit).split(b'\0'):
        if not row:
            continue
        header, name = row.split(b'\t', 1)
        mode, kind, oid, size = header.decode().split()
        if kind != 'blob':
            raise ValueError('Unsupported non-blob entry')
        result[name.decode('utf-8')] = {'mode': mode, 'oid': oid, 'size': int(size)}
    return result


def payload_at(commit):
    baseline, final = files_at(BASE), files_at(commit)
    updates = {}
    for name in sorted(baseline.keys() | final.keys()):
        if baseline.get(name) == final.get(name):
            continue
        if name not in final:
            updates[name] = None
        else:
            updates[name] = dict(final[name], text=git('cat-file', 'blob', final[name]['oid']).decode('utf-8'))
    return {'base_commit': BASE, 'source_commit': commit,
            'source_tree': git('rev-parse', commit + '^{tree}').decode().strip(),
            'commit_raw': git('cat-file', 'commit', commit).decode('utf-8'),
            'files': baseline, 'updates': updates}


def render(payload):
    template = (DIRECTORY / 'build_single_entry.py.in').read_text(encoding='utf-8')
    result = template.replace('@PAYLOAD@', pprint.pformat(payload, width=110, sort_dicts=False), 1)
    ast.parse(result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    if git('status', '--porcelain').strip():
        raise SystemExit('Commit the reviewed changes before generating a source delivery')
    commit = git('rev-parse', 'HEAD').decode().strip()
    result = render(payload_at(commit))
    args.output.write_text(result, encoding='utf-8', newline='\n')
    print('SINGLE_BUILD_SCRIPT=' + str(args.output.absolute()))
    print('SOURCE_COMMIT=' + commit)
    print('BYTES=' + str(args.output.stat().st_size))
    print('NO_TARGET_BUILD_OR_NETWORK_CALLS')


if __name__ == '__main__':
    main()
