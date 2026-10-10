#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Thomas Vincent
# SPDX-License-Identifier: GPL-2.0-or-later
"""Run the actual workflow gate with deterministic analyzer outcomes."""

import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


WORKFLOW = Path(__file__).resolve().parents[2] / '.github/workflows/static-analysis.yml'
STEP = '      - name: Run clang-tidy on the production sources\n        run: |\n'
SCRIPT = textwrap.dedent(WORKFLOW.read_text().split(STEP, 1)[1].split('\n      - name:', 1)[0])


class ClangTidyGateTests(unittest.TestCase):
    def run_gate(self, stdout='', stderr='', status=0, baseline='', make_status=0):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '.github').mkdir()
            (root / '.github/clang-tidy-baseline.txt').write_text(baseline)
            (root / 'stdout.txt').write_text(stdout)
            (root / 'stderr.txt').write_text(stderr)
            analyzer = root / 'clang-tidy'
            analyzer.write_text('#!/bin/sh\ncat stdout.txt\ncat stderr.txt >&2\n'
                                f'exit {status}\n')
            make = root / 'make'
            make.write_text('#!/bin/sh\nprintf "src/example.c\\n"\n'
                            f'exit {make_status}\n')
            analyzer.chmod(0o755)
            make.chmod(0o755)
            environment = dict(os.environ, PATH=f'{root}:{os.environ["PATH"]}', CHECKS='-*')
            return subprocess.run(['bash', '-c', SCRIPT], cwd=root, env=environment,
                                  text=True, capture_output=True)

    def test_clean_analysis_and_reviewed_warnings_pass(self):
        self.assertEqual(self.run_gate().returncode, 0)
        result = self.run_gate(stdout='src/example.c:1:2: warning: reviewed [bugprone-test]\n',
                               baseline='src/example.c: reviewed [bugprone-test]\n')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_new_warnings_fail(self):
        result = self.run_gate(stdout='src/example.c:1:2: warning: new [bugprone-test]\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('New clang-tidy findings:', result.stdout)

    def test_analyzer_failures_cannot_pass_as_zero_findings(self):
        for status in (1, 127, 139):
            with self.subTest(status=status):
                result = self.run_gate(stderr='analyzer failed\n', status=status)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('analyzer failed', result.stdout)

    def test_compilation_errors_fail_even_with_zero_exit_status(self):
        diagnostic = 'src/example.c:1:2: error: missing header [clang-diagnostic-error]\n'
        for stream in ('stdout', 'stderr'):
            with self.subTest(stream=stream):
                result = self.run_gate(**{stream: diagnostic})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('compilation error', result.stdout)

    def test_source_enumeration_failures_fail(self):
        self.assertNotEqual(self.run_gate(make_status=2).returncode, 0)


if __name__ == '__main__':
    unittest.main()
