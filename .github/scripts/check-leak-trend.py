#!/usr/bin/env python3
"""Parse sanitizer/valgrind logs and enforce nightly leak thresholds."""

from __future__ import annotations

import argparse
import glob
import json
import re
from pathlib import Path


DEF_RE = re.compile(r"definitely lost:\s*([0-9,]+)\s+bytes")
IND_RE = re.compile(r"indirectly lost:\s*([0-9,]+)\s+bytes")
POS_RE = re.compile(r"possibly lost:\s*([0-9,]+)\s+bytes")
ERR_RE = re.compile(r"ERROR SUMMARY:\s*([0-9,]+)\s+errors")


def as_int(value: str) -> int:
	return int(value.replace(",", ""))


def parse_valgrind(log_text: str) -> dict[str, int]:
	return {
		"definitely_lost_bytes": sum(as_int(v) for v in DEF_RE.findall(log_text)),
		"indirectly_lost_bytes": sum(as_int(v) for v in IND_RE.findall(log_text)),
		"possibly_lost_bytes": sum(as_int(v) for v in POS_RE.findall(log_text)),
		"error_summary": sum(as_int(v) for v in ERR_RE.findall(log_text)),
	}


def parse_asan(log_text: str) -> dict[str, int]:
	return {
		"asan_error_events": len(re.findall(r"AddressSanitizer", log_text)),
		"ubsan_error_events": len(re.findall(r"runtime error:", log_text)),
	}


def collect_text(patterns: list[str]) -> str:
	parts: list[str] = []
	for pat in patterns:
		matches = sorted(glob.glob(pat))
		for path in matches:
			try:
				parts.append(Path(path).read_text(encoding="utf-8", errors="replace"))
			except OSError:
				continue
	return "\n".join(parts)


def enforce(summary: dict[str, int], baseline: dict[str, int]) -> list[str]:
	failures: list[str] = []
	for key, value in summary.items():
		limit = int(baseline.get(f"max_{key}", 0))
		if value > limit:
			failures.append(f"{key}={value} exceeded max_{key}={limit}")
	return failures


def main() -> int:
	parser = argparse.ArgumentParser()
	parser.add_argument("--mode", choices=("valgrind", "asan"), required=True)
	parser.add_argument("--baseline", required=True)
	parser.add_argument("--output", required=True)
	parser.add_argument("--logs", nargs="+", required=True)
	args = parser.parse_args()

	baseline_doc = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
	mode_cfg = baseline_doc.get(args.mode, {})
	text = collect_text(args.logs)

	if args.mode == "valgrind":
		summary = parse_valgrind(text)
	else:
		summary = parse_asan(text)

	Path(args.output).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

	failures = enforce(summary, mode_cfg)
	if failures:
		print("Leak trend gate failed:")
		for line in failures:
			print(f"- {line}")
		return 1

	print(f"{args.mode} leak trend gate passed.")
	print(json.dumps(summary, indent=2))
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
