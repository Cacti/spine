#!/usr/bin/env python3
"""Convert clang-tidy text output to SARIF 2.1.0."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


LINE_RE = re.compile(
	r"^(?P<file>[^:\n]+):(?P<line>\d+):(?P<col>\d+):\s+"
	r"(?P<severity>warning|error|note):\s+"
	r"(?P<message>.*?)(?:\s+\[(?P<rule>[^\]]+)\])?\s*$"
)


def level_from_severity(severity: str) -> str:
	if severity == "error":
		return "error"
	if severity == "warning":
		return "warning"
	return "note"


def build_sarif(results: list[dict], rules: dict[str, dict]) -> dict:
	return {
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": [
			{
				"tool": {
					"driver": {
						"name": "clang-tidy",
						"informationUri": "https://clang.llvm.org/extra/clang-tidy/",
						"rules": sorted(rules.values(), key=lambda r: r["id"]),
					}
				},
				"results": results,
			}
		],
	}


def main() -> int:
	if len(sys.argv) != 3:
		print("usage: clang_tidy_to_sarif.py <input.txt> <output.sarif>", file=sys.stderr)
		return 2

	in_path = Path(sys.argv[1])
	out_path = Path(sys.argv[2])
	text = in_path.read_text(encoding="utf-8", errors="replace") if in_path.exists() else ""

	results = []
	seen = set()
	rules: dict[str, dict] = {}

	for raw_line in text.splitlines():
		m = LINE_RE.match(raw_line)
		if not m:
			continue

		rule_id = m.group("rule") or "clang-tidy"
		file_path = m.group("file")
		line = int(m.group("line"))
		col = int(m.group("col"))
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
	out_path.write_text(json.dumps(sarif, indent=2) + "\n", encoding="utf-8")
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
