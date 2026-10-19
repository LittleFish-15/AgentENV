"""Generate a readable, uncompressed standalone .py delivery from actual sources."""
import argparse
import ast
from pathlib import Path
import subprocess

DIRECTORY = Path(__file__).resolve().parent


def render(commit):
    parts = []
    for name in ('bridge.cpp', 'ub_layer_broker.py', 'sdk_smoke.py'):
        source = (DIRECTORY / name).read_text(encoding='utf-8')
        if "'''" in source or source.endswith('\\'):
            raise ValueError('Payload needs a different raw string delimiter: ' + name)
        parts.append(repr(name) + ": r'''" + source + "'''")
    template = (DIRECTORY / 'single_file_entry.py.in').read_text(encoding='utf-8')
    result = template.replace('@SOURCE_COMMIT@', commit).replace('@PAYLOADS@', '{\n' + ',\n'.join(parts) + '\n}')
    ast.parse(result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=DIRECTORY).decode().strip()
    result = render(commit)
    args.output.write_text(result, encoding='utf-8', newline='\n')
    print('SINGLE_FILE_CREATED=' + str(args.output.absolute()))
    print('BYTES=' + str(args.output.stat().st_size))
    print('SOURCE_COMMIT=' + commit)
    print('NO_SDK_OR_REMOTE_CALLS')


if __name__ == '__main__':
    main()
