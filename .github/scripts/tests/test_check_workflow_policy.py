#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "check-workflow-policy.py"
SPEC = importlib.util.spec_from_file_location("check_workflow_policy", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)


class CheckWorkflowPolicyTest(unittest.TestCase):
	def test_pinned_sha_passes(self) -> None:
		violations: list[str] = []
		policy.check_uses(".github/workflows/ci.yml", "checkout", "actions/checkout@0123456789abcdef0123456789abcdef01234567", violations)

		self.assertEqual(violations, [])

	def test_missing_ref_fails(self) -> None:
		violations: list[str] = []
		policy.check_uses(".github/workflows/ci.yml", "checkout", "actions/checkout", violations)

		self.assertIn("uses reference is missing @ref", violations[0])

	def test_branch_ref_fails(self) -> None:
		violations: list[str] = []
		policy.check_uses(".github/workflows/ci.yml", "checkout", "actions/checkout@v4", violations)

		self.assertIn("action ref must be a pinned SHA", violations[0])

	def test_multiline_run_requires_strict_mode(self) -> None:
		violations: list[str] = []
		policy.check_run(".github/workflows/ci.yml", "build", "echo one\necho two\n", violations, {})

		self.assertIn("multiline run must start", violations[0])

	def test_curl_pipe_fails_without_allowlist_token(self) -> None:
		violations: list[str] = []
		policy.check_run(".github/workflows/ci.yml", "install", "set -euo pipefail\ncurl https://example.invalid/install | sh\n", violations, {})

		self.assertIn("curl|sh is not allowlisted", violations[0])

	def test_curl_pipe_passes_with_allowlist_token(self) -> None:
		violations: list[str] = []
		run = "set -euo pipefail\ncurl https://example.invalid/install | sh\n"
		policy.check_run(".github/workflows/ci.yml", "install", run, violations, {".github/workflows/ci.yml": ["example.invalid/install"]})

		self.assertEqual(violations, [])


if __name__ == "__main__":
	unittest.main()
