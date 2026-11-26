#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Write THIRD_PARTY_NOTICES for a MyDC release to stdout.

Usage: python3 -I tools/publish/notices.py <go-licenses save dir> <package-lock.json>

The Go part reads the tree that `go-licenses save` wrote (one directory per
module with its LICENSE and NOTICE files). The web part covers the npm packages
bundled into the UI (non-dev entries of package-lock.json) and reads their
license files from node_modules next to the lock file, so run `npm ci` first.
"""
import json, os, re, sys

MIT_TEXT = """MIT License

Copyright (c) {holder}

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
LICENSE_FILE = re.compile(r'(?i)^(licen[cs]e|copying|notice)(\..*)?$')


def files_in(d):
    try:
        names = sorted(os.listdir(d))
    except OSError:
        return []
    return [os.path.join(d, n) for n in names if LICENSE_FILE.match(n) and os.path.isfile(os.path.join(d, n))]


def section(title, paths, out, text=''):
    out.write('=' * 78 + '\n' + title + '\n' + '=' * 78 + '\n\n' + text)
    for p in paths:
        with open(p, encoding='utf-8', errors='replace') as f:
            out.write(f.read().rstrip() + '\n\n')


def go_modules(root, out):
    found = 0
    for d, _, _ in sorted(os.walk(root)):
        paths = files_in(d)
        if paths:
            section(os.path.relpath(d, root), paths, out)
            found += 1
    return found


def read_json(p):
    try:
        with open(p, encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def npm_packages(lock, out):
    base = os.path.dirname(os.path.abspath(lock))
    with open(lock, encoding='utf-8') as f:
        packages = json.load(f).get('packages', {})
    missing = []
    for key, meta in sorted(packages.items()):
        if not key or meta.get('dev'):
            continue
        name = key.split('node_modules/')[-1]
        paths = files_in(os.path.join(base, key))
        if not paths:
            # Some packages (rete*) ship no license file. For MIT, the package
            # metadata names the holder, which is all the notice needs.
            pkg = read_json(os.path.join(base, key, 'package.json'))
            author = pkg.get('author')
            holder = author.get('name') if isinstance(author, dict) else author
            if meta.get('license') != 'MIT' or not holder:
                missing.append(name)
                continue
            repo = pkg.get('repository')
            repo = repo.get('url') if isinstance(repo, dict) else repo
            text = MIT_TEXT.format(holder=holder) + (f'\nSource: {repo}\n' if repo else '') + '\n'
            section(f'{name} {meta.get("version", "")} (MIT)', [], out, text)
            continue
        section(f'{name} {meta.get("version", "")} ({meta.get("license", "?")})', paths, out)
    return missing


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    out = sys.stdout
    out.write('MyDC third-party notices\n\nThis file lists the licenses and notices of third-party software included\n'
              'in MyDC release binaries and images.\n\n')
    if go_modules(sys.argv[1], out) == 0:
        sys.exit('no Go license files under ' + sys.argv[1])
    missing = npm_packages(sys.argv[2], out)
    if missing:
        sys.exit('npm packages without a license file: ' + ', '.join(missing))


if __name__ == '__main__':
    main()
