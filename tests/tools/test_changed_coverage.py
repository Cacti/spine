#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The Cacti Group
# SPDX-License-Identifier: LGPL-2.1-or-later
import unittest
from verify_changed_coverage import verify


class ChangedCoverageTests(unittest.TestCase):
    profile = '<coverage><class filename="src/new.c"><lines><line number="3" hits="1"/><line number="4" hits="0"/></lines></class></coverage>'
    diff = 'diff --git a/src/new.c b/src/new.c\n+++ b/src/new.c\n@@ -0,0 +3,2 @@\n+executed();\n+unexecuted();\n'

    def test_uncovered_line_fails(self):
        self.assertEqual(verify(self.profile, self.diff), (2, ['src/new.c:4']))

    def test_full_coverage_and_multiple_producers(self):
        profile = self.profile.replace('hits="0"', 'hits="1"')
        self.assertEqual(verify(profile, self.diff), (2, []))
        duplicate = self.profile.replace('</coverage>', profile.removeprefix('<coverage>'))
        self.assertEqual(verify(duplicate, self.diff), (2, []))

    def test_missing_measured_source_fails(self):
        extra = self.diff + '+++ b/src/missing.c\n@@ -0,0 +1 @@\n+missing();\n'
        self.assertEqual(verify(self.profile, extra)[1], ['src/new.c:4', 'src/missing.c: missing measured source'])

    def test_empty_measurement_and_bad_hunks_are_rejected(self):
        self.assertEqual(verify(self.profile, ''), (0, []))
        self.assertEqual(verify(self.profile, self.diff.replace('+3,2', '+70,2')), (0, []))
        with self.assertRaises(ValueError):
            verify(self.profile, self.diff.replace('@@ -0,0 +3,2 @@', '@@ malformed'))


if __name__ == '__main__':
    unittest.main()
