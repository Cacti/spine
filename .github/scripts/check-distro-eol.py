#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-only
#
# Fork maintenance: Thomas Vincent.
# Project contributor history: CONTRIBUTORS.md.
"""Fail when a distro-matrix lane has reached its vendor end of life.

The release data comes from https://endoflife.date. A lane whose release is
missing from the API, or an API that cannot be reached, also fails: a lane
that cannot be checked is not known to be supported.
"""

import datetime
import json
import sys
import urllib.request

API = 'https://endoflife.date/api/v1/products/{}/'

# (lane, endoflife.date product, release). Keep in step with
# .github/workflows/distro-matrix.yml and scripts/test-distros.sh.
LANES = [
    ('rockylinux/rockylinux:8', 'rocky-linux', '8'),
    ('rockylinux/rockylinux:9', 'rocky-linux', '9'),
    ('rockylinux/rockylinux:10', 'rocky-linux', '10'),
    ('almalinux:8', 'almalinux', '8'),
    ('almalinux:9', 'almalinux', '9'),
    ('almalinux:10', 'almalinux', '10'),
    ('ubuntu:22.04', 'ubuntu', '22.04'),
    ('ubuntu:24.04', 'ubuntu', '24.04'),
    ('ubuntu:26.04', 'ubuntu', '26.04'),
    ('debian:12', 'debian', '12'),
    ('debian:13', 'debian', '13'),
    ('fedora:44', 'fedora', '44'),
    ('opensuse/leap:16.0', 'opensuse', '16.0'),
    ('alpine:3.24', 'alpine-linux', '3.24'),
    ('FreeBSD 14.5', 'freebsd', '14.5'),
    ('FreeBSD 15.1', 'freebsd', '15.1'),
    ('NetBSD 10.1', 'netbsd', '10'),
    ('NetBSD 11.0', 'netbsd', '11'),
    ('OpenBSD 7.9', 'openbsd', '7.9'),
]


def fetch(product: str) -> dict[str, dict[str, object]]:
    request = urllib.request.Request(
        API.format(product), headers={'User-Agent': 'spine-distro-eol-check'}
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        body = json.load(response)
    return {release['name']: release for release in body['result']['releases']}


def main() -> int:
    today = datetime.date.today()
    releases: dict[str, dict[str, dict[str, object]]] = {}
    failures = 0

    for lane, product, name in LANES:
        if product not in releases:
            releases[product] = fetch(product)
        release = releases[product].get(name)
        if release is None:
            print(f'{lane}: {product} {name} is not listed by endoflife.date')
            failures += 1
            continue

        eol = release.get('eolFrom')
        ended = bool(release.get('isEol'))
        if isinstance(eol, str) and datetime.date.fromisoformat(eol) <= today:
            ended = True
        if ended:
            print(f'{lane}: {product} {name} reached end of life on {eol}')
            failures += 1
        else:
            print(f'{lane}: supported until {eol or "no announced date"}')

    if failures:
        print(f'{failures} lane(s) are past end of life or unknown; '
              'remove or replace them in the distro matrix.')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
