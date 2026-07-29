#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1]


def load_script(name: str):
	spec = importlib.util.spec_from_file_location(name.replace("-", "_"), SCRIPT_DIR / name)
	assert spec is not None and spec.loader is not None
	module = importlib.util.module_from_spec(spec)
	spec.loader.exec_module(module)
	return module


class SarifConverterTest(unittest.TestCase):
	def run_converter(self, script: str, input_text: str) -> tuple[subprocess.CompletedProcess[str], dict | None]:
		with tempfile.TemporaryDirectory() as td:
			tmp = Path(td)
			in_path = tmp / "input.txt"
			out_path = tmp / "output.sarif"
			in_path.write_text(input_text, encoding="utf-8")
			result = subprocess.run(
				[sys.executable, str(SCRIPT_DIR / script), str(in_path), str(out_path)],
				capture_output=True,
				text=True,
				check=False,
			)
			sarif = json.loads(out_path.read_text(encoding="utf-8")) if out_path.exists() else None
		return result, sarif

	def test_clang_tidy_deduplicates_and_aggregates_rules(self) -> None:
		line = "src/a.c:7:3: warning: message [modernize-use-nullptr]\n"
		result, sarif = self.run_converter("clang_tidy_to_sarif.py", line + line)

		self.assertEqual(result.returncode, 0)
		self.assertIsNotNone(sarif)
		run = sarif["runs"][0]
		self.assertEqual(len(run["results"]), 1)
		self.assertEqual(run["results"][0]["locations"][0]["physicalLocation"]["region"], {"startLine": 7, "startColumn": 3})
		self.assertEqual([rule["id"] for rule in run["tool"]["driver"]["rules"]], ["modernize-use-nullptr"])

	def test_cppcheck_maps_information_to_note_and_defaults_missing_col(self) -> None:
		result, sarif = self.run_converter("cppcheck_to_sarif.py", "src/a.c:9: information: info [unusedFunction]\n")

		self.assertEqual(result.returncode, 0)
		self.assertIsNotNone(sarif)
		entry = sarif["runs"][0]["results"][0]
		self.assertEqual(entry["level"], "note")
		self.assertEqual(entry["locations"][0]["physicalLocation"]["region"], {"startLine": 9, "startColumn": 1})

	def test_converters_reject_non_positive_location_values_without_traceback(self) -> None:
		for script, module_name in (
			("clang_tidy_to_sarif.py", "clang_tidy_to_sarif"),
			("cppcheck_to_sarif.py", "cppcheck_to_sarif"),
		):
			module = load_script(script)
			with self.assertRaises(ValueError):
				module.parse_positive_int("0", "line", "tool output")


if __name__ == "__main__":
	unittest.main()
