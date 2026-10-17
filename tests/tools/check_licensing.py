#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The Cacti Group
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Check that source files carry SPDX headers and that Debian packaging agrees.

Every tracked C, shell, Python and awk file, plus the Autotools inputs, must
name its license in an SPDX-License-Identifier line. packaging/debian/copyright
must then give each file that identifier. Vendored code and generated files are
exempt from the header rule; vendored code is covered by its own stanza.
"""
import fnmatch
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
HEADER_SUFFIXES = {'.c', '.h', '.sh', '.py', '.awk'}
HEADER_NAMES = {'Makefile.am', 'configure.ac', 'bootstrap'}
EXEMPT_PREFIXES = ('vendor/', 'LICENSES/')
SPDX = re.compile(r'SPDX-License-Identifier:\s*(.+?)\s*(?:\*/)?\s*$')


def tracked_files():
    try:
        out = subprocess.run(['git', '-C', str(ROOT), 'ls-files', '-z'], check=True,
                             capture_output=True, text=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    return [name for name in out.split('\0') if name]


def spdx_of(path):
    try:
        with open(ROOT / path, encoding='utf-8', errors='replace') as handle:
            for _ in range(40):
                line = handle.readline()
                if not line:
                    break
                match = SPDX.search(line)
                if match:
                    return match.group(1)
    except OSError:
        return None
    return None


def needs_header(path):
    if path.startswith(EXEMPT_PREFIXES):
        return False
    name = path.rsplit('/', 1)[-1]
    return name in HEADER_NAMES or Path(path).suffix in HEADER_SUFFIXES


def debian_stanzas():
    text = (ROOT / 'packaging/debian/copyright').read_text()
    stanzas = []
    for block in re.split(r'\n\s*\n', text):
        files, license_name = [], None
        field = None
        for line in block.splitlines():
            if line.startswith(('Files:', 'License:')):
                field, value = line.split(':', 1)
                value = value.strip()
                if field == 'Files':
                    files.extend(value.split())
                else:
                    license_name = value.split('\n')[0]
            elif line[:1] in (' ', '\t') and field == 'Files':
                files.extend(line.split())
            elif line and not line[0].isspace():
                field = None
        if files and license_name:
            stanzas.append((files, license_name))
    return stanzas


def normalize(expression):
    return re.sub(r'\s+', ' ', expression.replace('(', ' ').replace(')', ' ')).strip().lower()


def debian_license(path, stanzas):
    chosen = None
    for patterns, license_name in stanzas:
        if any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns):
            chosen = license_name
    return chosen


def main():
    files = tracked_files()
    if files is None:
        print('not a git checkout; skipping')
        return 77
    stanzas = debian_stanzas()
    problems = []
    for path in files:
        identifier = spdx_of(path)
        if identifier is None:
            if needs_header(path):
                problems.append(f'{path}: no SPDX-License-Identifier header')
            continue
        if path.startswith(EXEMPT_PREFIXES):
            continue
        covered = debian_license(path, stanzas)
        if covered is None or normalize(covered) != normalize(identifier):
            problems.append(f'{path}: header says {identifier}, packaging/debian/copyright says {covered}')
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        print(f'{len(problems)} licensing problem(s)', file=sys.stderr)
        return 1
    print('licensing headers and Debian copyright agree')
    return 0


if __name__ == '__main__':
    sys.exit(main())
