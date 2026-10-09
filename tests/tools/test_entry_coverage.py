#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-only
# Fork maintenance: Thomas Vincent. Project contributor history: CONTRIBUTORS.md.
"""Exercise measured zero-branch normalization without weakening verification."""
import copy
from pathlib import Path
import unittest

from normalize_entry_coverage import normalize


class EntryCoverageTests(unittest.TestCase):
    def setUp(self):
        self.entry = Path('/source/main.c')
        self.profile = ('SF:/source/main.c\nFNF:1\nFNH:1\nLF:2\nLH:2\nend_of_record\n'
                        'SF:/source/other.c\nBRF:2\nBRH:1\nend_of_record\n')
        self.report = {'current_working_directory': '/source', 'files': [{
            'file': 'main.c', 'functions': [{'name': 'main', 'execution_count': 2}],
            'lines': [{'branches': []}, {'branches': []}]}]}

    def test_supplies_measured_zero_and_preserves_other_source(self):
        output = normalize(self.profile, self.report, self.entry)
        self.assertIn('LH:2\nBRF:0\nBRH:0\nend_of_record', output)
        self.assertTrue(output.endswith('SF:/source/other.c\nBRF:2\nBRH:1\nend_of_record\n'))
        self.assertEqual(normalize(output, self.report, self.entry), output)

    def test_rejects_missing_mismatched_unexecuted_and_branchful_evidence(self):
        for change in ('missing', 'wrong-source', 'unexecuted', 'branches', 'no-branch-data'):
            with self.subTest(change=change):
                report = copy.deepcopy(self.report)
                measured = report['files'][0]
                if change == 'missing':
                    report['files'] = []
                elif change == 'wrong-source':
                    measured['file'] = 'other.c'
                elif change == 'unexecuted':
                    measured['functions'][0]['execution_count'] = 0
                elif change == 'branches':
                    measured['lines'][0]['branches'] = [{'count': 1}]
                else:
                    del measured['lines'][0]['branches']
                with self.assertRaises(ValueError):
                    normalize(self.profile, report, self.entry)

    def test_rejects_absent_duplicate_or_contradictory_lcov_entry(self):
        for profile in ('', self.profile + self.profile,
                        self.profile.replace('LF:2', 'BRDA:1,0,0,1\nLF:2'),
                        self.profile.replace('LF:2', 'BRF:1\nBRH:0\nLF:2')):
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                normalize(profile, self.report, self.entry)


if __name__ == '__main__':
    unittest.main()
