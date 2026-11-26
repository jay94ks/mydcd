#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Check relative Markdown links (files and #anchors) in the active docs.

Usage: python3 -I tools/check-links.py [--fix-moved OLD=NEW ...]
Skips archives and raw verification records. Exit code 1 if a link is broken.
"""
import os, re, sys, unicodedata

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP = ('devel/testing/results', 'devel/archive', 'backups', '3rd-party', 'work', 'publish/overlay')  # overlay links resolve in the public tree; export.py checks them there
SKIP_NAMES = {'node_modules', '.git', 'dist'}
LINK = re.compile(r'(?<!!)\[[^\]]*\]\(([^)\s]+)\)')

def md_files():
    for d, dirs, files in os.walk(ROOT):
        rel = os.path.relpath(d, ROOT)
        dirs[:] = [x for x in dirs if x not in SKIP_NAMES and not any(os.path.join(rel, x).lstrip('./').startswith(s) for s in SKIP)]
        for f in files:
            if f.endswith('.md'):
                yield os.path.join(d, f)

def slug(h):
    h = unicodedata.normalize('NFC', h.strip().lower())
    h = re.sub(r'<[^>]+>', '', h)
    h = re.sub(r'[^\w\- ]', '', h)
    return h.replace(' ', '-')

_anchors = {}
def anchors(path):
    if path not in _anchors:
        found, seen = set(), {}
        try:
            text = open(path, encoding='utf-8').read()
        except OSError:
            text = ''
        for m in re.finditer(r'^#{1,6}\s+(.*)$', text, re.M):
            s = slug(m.group(1).strip('# '))
            n = seen.get(s, 0)
            found.add(s if n == 0 else f'{s}-{n}')
            seen[s] = n + 1
        for m in re.finditer(r'<a\s+(?:id|name)="([^"]+)"', text):
            found.add(m.group(1))
        _anchors[path] = found
    return _anchors[path]

def main():
    moves = dict(a.split('=', 1) for a in sys.argv[1:] if '=' in a)
    broken = 0
    for f in md_files():
        text = open(f, encoding='utf-8').read()
        out, changed = text, False
        for m in LINK.finditer(text):
            target = m.group(1)
            if re.match(r'^[a-z]+:', target) or target.startswith('#') and False:
                continue
            path, _, anchor = target.partition('#')
            dest = os.path.normpath(os.path.join(os.path.dirname(f), path)) if path else f
            relroot = os.path.relpath(dest, ROOT)
            if relroot in moves:
                new = os.path.relpath(os.path.join(ROOT, moves[relroot]), os.path.dirname(f))
                out = out.replace('](' + target + ')', '](' + new + ('#' + anchor if anchor else '') + ')')
                changed = True
                dest = os.path.join(ROOT, moves[relroot])
            if not os.path.exists(dest):
                print(f'{os.path.relpath(f, ROOT)}: missing {target}')
                broken += 1
            elif anchor and dest.endswith('.md') and anchor not in anchors(dest):
                print(f'{os.path.relpath(f, ROOT)}: missing anchor {target}')
                broken += 1
        if changed:
            open(f, 'w', encoding='utf-8').write(out)
    sys.exit(1 if broken else 0)

main()
