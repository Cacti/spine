#!/usr/bin/env python3
"""Convert cppcheck text output to SARIF 2.1.0."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


LINE_RE = re.compile(
	r"^(?P<file>[^:\n]+):(?P<line>\d+)(?::(?P<col>\d+))?:\s+"
	r"(?P<severity>error|warning|style|performance|portability|information):\s+"
	r"(?P<message>.*?)(?:\s+\[(?P<rule>[^\]]+)\])?\s*$"
)


def level_from_severity(severity: str) -> str:
	if severity == "error":
		return "error"
	if severity == "warning":
		return "warning"
	return "note"


def parse_positive_int(raw: str, field: str, line: str) -> int:
	try:
		value = int(raw)
	except ValueError as exc:
		raise ValueError(f"invalid {field} value in cppcheck line: {line}") from exc
	if value < 1:
		raise ValueError(f"invalid {field} value in cppcheck line: {line}")
	return value


def build_sarif(results: list[dict], rules: dict[str, dict]) -> dict:
	return {
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": [
			{
				"tool": {
					"driver": {
						"name": "cppcheck",
						"informationUri": "https://cppcheck.sourceforge.io/",
						"rules": sorted(rules.values(), key=lambda r: r["id"]),
					}
				},
				"results": results,
			}
		],
	}


def main() -> int:
	if len(sys.argv) != 3:
		print("usage: cppcheck_to_sarif.py <input.txt> <output.sarif>", file=sys.stderr)
		return 2

	in_path = Path(sys.argv[1])
	out_path = Path(sys.argv[2])
	try:
		text = in_path.read_text(encoding="utf-8", errors="replace") if in_path.exists() else ""
	except OSError as exc:
		print(f"Failed to read cppcheck input '{in_path}': {exc}", file=sys.stderr)
		return 2

	results = []
	seen = set()
	rules: dict[str, dict] = {}

	for raw_line in text.splitlines():
		m = LINE_RE.match(raw_line)
		if not m:
			continue

		rule_id = m.group("rule") or f"cppcheck-{m.group('severity')}"
		file_path = m.group("file")
		try:
			line = parse_positive_int(m.group("line"), "line", raw_line)
			col = parse_positive_int(m.group("col") or "1", "column", raw_line)
		except ValueError as exc:
			print(str(exc), file=sys.stderr)
			return 2
		message = m.group("message").strip()
		level = level_from_severity(m.group("severity"))
		key = (file_path, line, col, rule_id, message, level)
		if key in seen:
			continue
		seen.add(key)

		rules.setdefault(
			rule_id,
			{
				"id": rule_id,
				"shortDescription": {"text": rule_id},
			},
		)

		results.append(
			{
				"ruleId": rule_id,
				"level": level,
				"message": {"text": message},
				"locations": [
					{
						"physicalLocation": {
							"artifactLocation": {"uri": file_path},
							"region": {"startLine": line, "startColumn": col},
						}
					}
				],
			}
		)

	sarif = build_sarif(results, rules)
	try:
		out_path.write_text(json.dumps(sarif, indent=2) + "\n", encoding="utf-8")
	except OSError as exc:
		print(f"Failed to write SARIF output '{out_path}': {exc}", file=sys.stderr)
		return 2

	return 0


if __name__ == "__main__":
	raise SystemExit(main())
