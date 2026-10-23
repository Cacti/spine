#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The Cacti Group
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Require measured coverage for every changed executable production C line."""
import argparse
import re
import xml.etree.ElementTree as ET


def verify(profile: str, diff: str) -> tuple[int, list[str]]:
    if diff.strip() and not diff.startswith('diff --git '):
        raise ValueError('Expected a unified Git diff; disable external diff and text conversion')
    measured = {}
    for item in ET.fromstring(profile).findall('.//class'):
        name = item.attrib['filename'].removeprefix('./')
        lines = measured.setdefault(name, {})
        for line in item.findall('./lines/line'):
            number = int(line.attrib['number'])
            lines[number] = max(lines.get(number, 0), int(line.attrib['hits']))
    changed = {}
    current = None
    position = 0
    for line in diff.splitlines():
        if line.startswith('+++ b/'):
            current = line[6:]
        elif line.startswith('@@ '):
            match = re.search(r'\+(\d+)(?:,\d+)? @@', line)
            if match is None:
                raise ValueError('Malformed diff hunk')
            position = int(match.group(1))
        elif line.startswith('+') and not line.startswith('+++'):
            if current and current.startswith('src/') and current.endswith('.c'):
                changed.setdefault(current, set()).add(position)
            position += 1
        elif not line.startswith(('-', '\\', 'diff ', 'index ', '--- ')):
            position += 1
    missing = []
    total = 0
    for name, numbers in changed.items():
        if name not in measured:
            missing.append(f'{name}: missing measured source')
            continue
        for number in sorted(numbers & measured[name].keys()):
            total += 1
            if measured[name][number] == 0:
                missing.append(f'{name}:{number}')
    return total, missing


def main() -> None:
    from pathlib import Path
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('profile', type=Path)
    parser.add_argument('diff', type=Path)
    arguments = parser.parse_args()
    total, missing = verify(arguments.profile.read_text(), arguments.diff.read_text())
    for line in missing:
        print('UNCOVERED:', line)
    if missing:
        raise SystemExit(1)
    if total == 0:
        print('No changed executable production lines; coverage gate is not applicable')
    else:
        print(f'Changed executable production lines: {total}/{total} covered (100%)')


if __name__ == '__main__':
    main()
