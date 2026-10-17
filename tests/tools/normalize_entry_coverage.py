#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-only
# Fork maintenance: Thomas Vincent. Project contributor history: CONTRIBUTORS.md.
"""Supply LCOV's omitted zero totals only for a measured branchless main."""
import argparse
import json
from pathlib import Path


def normalize(profile: str, report: dict, entry: Path) -> str:
    """Reject missing/mismatched gcov evidence; retain every other LCOV record."""
    entry = entry.resolve()
    cwd = Path(report['current_working_directory'])
    files = [item for item in report['files']
             if (cwd / item['file']).resolve() == entry]
    if len(files) != 1:
        raise ValueError('Expected exactly one measured entry source')
    measured = files[0]
    functions = measured['functions']
    if (len(functions) != 1 or functions[0]['name'] != 'main'
            or functions[0]['execution_count'] <= 0):
        raise ValueError('Expected an executed main function')
    lines = measured['lines']
    if not lines or any(line.get('branches') != [] for line in lines):
        raise ValueError('Entry is not proven branchless by gcov -b')
    records = profile.split('end_of_record')
    found = 0
    for index, record in enumerate(records):
        fields = record.splitlines()
        if f'SF:{entry}' not in fields:
            continue
        found += 1
        if any(line.startswith('BRDA:') for line in fields):
            raise ValueError('LCOV contradicts branchless gcov evidence')
        totals = [line for line in fields if line.startswith(('BRF:', 'BRH:'))]
        if totals:
            if sorted(totals) != ['BRF:0', 'BRH:0']:
                raise ValueError('Invalid existing entry branch totals')
        else:
            records[index] = record + 'BRF:0\nBRH:0\n'
    if found != 1:
        raise ValueError('Expected exactly one LCOV entry record')
    return 'end_of_record'.join(records)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('profile', type=Path)
    parser.add_argument('gcov_json', type=Path)
    parser.add_argument('entry', type=Path)
    args = parser.parse_args()
    result = normalize(args.profile.read_text(), json.loads(args.gcov_json.read_text()), args.entry)
    args.profile.write_text(result)


if __name__ == '__main__':
    main()
