#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check that every MyDC source file carries the SPDX license header.

Usage: python3 -I tools/check-spdx.py [--fix]
Checks tracked .go/.ts/.tsx/.js/.mjs/.py/.sh files and Dockerfiles outside
3rd-party/ (upstream headers stay as they are), backups/, devel/ and work/.
--fix adds the header where it is missing. Exit code 1 if a file lacks it.
"""
import os, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LICENSE = 'Apache-2.0'
SKIP = ('3rd-party/', 'backups/', 'devel/', 'work/')
SLASH = ('.go', '.ts', '.tsx', '.js', '.mjs')
HASH = ('.py', '.sh')
TAG = 'SPDX-License-Identifier:'


def comment(path):
    name = os.path.basename(path)
    if path.endswith(SLASH):
        return '//'
    if path.endswith(HASH) or name == 'Dockerfile' or name.startswith('Dockerfile.') and not name.endswith('.dockerignore'):
        return '#'
    return None


def sources():
    out = subprocess.run(['git', '-C', ROOT, 'ls-files', '-z'], check=True, capture_output=True).stdout
    for rel in out.decode().split('\0'):
        if rel and not rel.startswith(SKIP) and '/testdata/' not in rel and comment(rel):
            yield rel


def fix(path, mark):
    with open(path, encoding='utf-8') as f:
        text = f.read()
    lines = text.splitlines(keepends=True)
    keep = 0
    # A shebang or a Dockerfile parser directive must stay on the first line.
    if lines and (lines[0].startswith('#!') or (mark == '#' and lines[0].lower().startswith('# syntax='))):
        keep = 1
    header = f'{mark} {TAG} {LICENSE}\n'
    rest = ''.join(lines[keep:])
    # A blank line keeps the header out of a Go package doc comment.
    sep = '' if rest.startswith('\n') else '\n'
    with open(path, 'w', encoding='utf-8') as f:
        f.write(''.join(lines[:keep]) + header + sep + rest)


def main():
    do_fix = '--fix' in sys.argv[1:]
    missing = []
    for rel in sources():
        path = os.path.join(ROOT, rel)
        with open(path, encoding='utf-8', errors='replace') as f:
            head = ''.join(f.readline() for _ in range(5))
        if TAG in head:
            continue
        if do_fix:
            fix(path, comment(rel))
        else:
            missing.append(rel)
    for rel in missing:
        print(f'{rel}: missing "{TAG} {LICENSE}"')
    return 1 if missing else 0


if __name__ == '__main__':
    sys.exit(main())
