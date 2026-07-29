#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "check-leak-trend.py"


class CheckLeakTrendTest(unittest.TestCase):
	def run_gate(self, tmp: Path, baseline: Path, log_pattern: str, mode: str = "valgrind") -> subprocess.CompletedProcess[str]:
		return subprocess.run(
			[
				sys.executable,
				str(SCRIPT),
				"--mode",
				mode,
				"--baseline",
				str(baseline),
				"--output",
				str(tmp / "summary.json"),
				"--logs",
				log_pattern,
			],
			capture_output=True,
			text=True,
			check=False,
		)

	def test_missing_baseline_fails_without_traceback(self) -> None:
		with tempfile.TemporaryDirectory() as td:
			tmp = Path(td)
			result = self.run_gate(tmp, tmp / "missing.json", str(tmp / "*.log"))

		self.assertEqual(result.returncode, 2)
		self.assertIn("Failed to read leak baseline", result.stderr)
		self.assertNotIn("Traceback", result.stderr + result.stdout)

	def test_malformed_baseline_fails_without_traceback(self) -> None:
		with tempfile.TemporaryDirectory() as td:
			tmp = Path(td)
			baseline = tmp / "baseline.json"
			baseline.write_text("{not-json", encoding="utf-8")
			result = self.run_gate(tmp, baseline, str(tmp / "*.log"))

		self.assertEqual(result.returncode, 2)
		self.assertIn("Failed to parse leak baseline", result.stderr)
		self.assertNotIn("Traceback", result.stderr + result.stdout)

	def test_comma_formatted_bytes_under_limit_pass(self) -> None:
		with tempfile.TemporaryDirectory() as td:
			tmp = Path(td)
			baseline = tmp / "baseline.json"
			baseline.write_text(json.dumps({"valgrind": {"max_definitely_lost_bytes": 1234}}), encoding="utf-8")
			(tmp / "valgrind.log").write_text("definitely lost: 1,234 bytes\n", encoding="utf-8")
			result = self.run_gate(tmp, baseline, str(tmp / "*.log"))

		self.assertEqual(result.returncode, 0)
		self.assertIn("valgrind leak trend gate passed", result.stdout)

	def test_comma_formatted_bytes_over_limit_fail(self) -> None:
		with tempfile.TemporaryDirectory() as td:
			tmp = Path(td)
			baseline = tmp / "baseline.json"
			baseline.write_text(json.dumps({"valgrind": {"max_definitely_lost_bytes": 1233}}), encoding="utf-8")
			(tmp / "valgrind.log").write_text("definitely lost: 1,234 bytes\n", encoding="utf-8")
			result = self.run_gate(tmp, baseline, str(tmp / "*.log"))

		self.assertEqual(result.returncode, 1)
		self.assertIn("definitely_lost_bytes=1234 exceeded max_definitely_lost_bytes=1233", result.stdout)

	def test_non_integer_baseline_limit_fails_without_traceback(self) -> None:
		with tempfile.TemporaryDirectory() as td:
			tmp = Path(td)
			baseline = tmp / "baseline.json"
			baseline.write_text(json.dumps({"valgrind": {"max_definitely_lost_bytes": "many"}}), encoding="utf-8")
			(tmp / "valgrind.log").write_text("definitely lost: 1 byte\n", encoding="utf-8")
			result = self.run_gate(tmp, baseline, str(tmp / "*.log"))

		self.assertEqual(result.returncode, 2)
		self.assertIn("max_definitely_lost_bytes must be an integer", result.stderr)
		self.assertNotIn("Traceback", result.stderr + result.stdout)

	def test_asan_over_limit_fails(self) -> None:
		with tempfile.TemporaryDirectory() as td:
			tmp = Path(td)
			baseline = tmp / "baseline.json"
			baseline.write_text(json.dumps({"asan": {"max_asan_error_events": 0}}), encoding="utf-8")
			(tmp / "asan.log").write_text("AddressSanitizer: heap-use-after-free\n", encoding="utf-8")
			result = self.run_gate(tmp, baseline, str(tmp / "*.log"), mode="asan")

		self.assertEqual(result.returncode, 1)
		self.assertIn("asan_error_events=1 exceeded max_asan_error_events=0", result.stdout)

	def test_empty_glob_uses_zero_summary(self) -> None:
		with tempfile.TemporaryDirectory() as td:
			tmp = Path(td)
			baseline = tmp / "baseline.json"
			baseline.write_text(json.dumps({"asan": {"max_asan_error_events": 0, "max_ubsan_error_events": 0}}), encoding="utf-8")
			result = self.run_gate(tmp, baseline, str(tmp / "*.missing"), mode="asan")
			summary = json.loads((tmp / "summary.json").read_text(encoding="utf-8"))

		self.assertEqual(result.returncode, 0)
		self.assertEqual(summary, {"asan_error_events": 0, "ubsan_error_events": 0})

	def test_valid_empty_baseline_uses_zero_limits(self) -> None:
		with tempfile.TemporaryDirectory() as td:
			tmp = Path(td)
			baseline = tmp / "baseline.json"
			baseline.write_text("{}", encoding="utf-8")
			result = self.run_gate(tmp, baseline, str(tmp / "*.missing"))

		self.assertEqual(result.returncode, 0)
		self.assertIn("valgrind leak trend gate passed", result.stdout)


if __name__ == "__main__":
	unittest.main()
