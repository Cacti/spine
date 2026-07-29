#!/usr/bin/env python3
"""Enforce workflow hygiene policy on GitHub Actions files."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml


PINNED_REF_RE = re.compile(r"^[0-9a-f]{40}$")
CURL_PIPE_RE = re.compile(r"curl\b[^\n|]*\|\s*(?:sh|bash)\b")
STRICT_LINE = "set -euo pipefail"
WORKFLOW_GLOB = ".github/workflows/*"
POLICY_CONFIG = ".github/workflow-policy.json"


def normalize_steps(job: dict) -> list[dict]:
	steps = job.get("steps")
	return steps if isinstance(steps, list) else []


def check_uses(path: str, step_name: str, uses_value: str, violations: list[str]) -> None:
	if uses_value.startswith("./") or uses_value.startswith("docker://"):
		return

	if "@" not in uses_value:
		violations.append(f"{path}:{step_name}: uses reference is missing @ref: {uses_value}")
		return

	ref = uses_value.split("@", 1)[1]
	if not PINNED_REF_RE.fullmatch(ref):
		violations.append(f"{path}:{step_name}: action ref must be a pinned SHA: {uses_value}")


def load_curl_pipe_allowlist(root: Path, violations: list[str]) -> dict[str, list[str]]:
	config_path = root / POLICY_CONFIG
	if not config_path.exists():
		return {}

	try:
		config = json.loads(config_path.read_text(encoding="utf-8"))
	except OSError as exc:
		violations.append(f"{POLICY_CONFIG}: failed to read policy config: {exc}")
		return {}
	except json.JSONDecodeError as exc:
		violations.append(f"{POLICY_CONFIG}: failed to parse policy config: {exc}")
		return {}

	allowlist = config.get("allowlist_curl_pipe", {})
	if not isinstance(allowlist, dict):
		violations.append(f"{POLICY_CONFIG}: allowlist_curl_pipe must be an object")
		return {}

	normalized: dict[str, list[str]] = {}
	for path, tokens in allowlist.items():
		if not isinstance(path, str) or not isinstance(tokens, list) or not all(isinstance(token, str) for token in tokens):
			violations.append(f"{POLICY_CONFIG}: allowlist_curl_pipe entries must map workflow paths to string token lists")
			continue
		normalized[path] = tokens

	return normalized


def check_run(path: str, step_name: str, run_value: str, violations: list[str], curl_pipe_allowlist: dict[str, list[str]]) -> None:
	lines = [ln.strip() for ln in run_value.splitlines() if ln.strip()]
	if not lines:
		return

	if len(run_value.splitlines()) > 1:
		if lines[0] != STRICT_LINE:
			violations.append(f"{path}:{step_name}: multiline run must start with '{STRICT_LINE}'")

	for match in CURL_PIPE_RE.finditer(run_value):
		_ = match
		allow_tokens = curl_pipe_allowlist.get(path, [])
		if not any(token in run_value for token in allow_tokens):
			violations.append(f"{path}:{step_name}: curl|sh is not allowlisted")


def main() -> int:
	root = Path(__file__).resolve().parents[2]
	workflow_files = sorted(
		p for p in root.glob(WORKFLOW_GLOB) if p.suffix in (".yml", ".yaml")
	)
	violations: list[str] = []
	curl_pipe_allowlist = load_curl_pipe_allowlist(root, violations)

	for wf in workflow_files:
		rel = str(wf.relative_to(root))
		try:
			doc = yaml.safe_load(wf.read_text(encoding="utf-8"))
		except OSError as exc:  # pragma: no cover
			violations.append(f"{rel}: failed to read YAML: {exc}")
			continue
		except yaml.YAMLError as exc:  # pragma: no cover
			violations.append(f"{rel}: failed to parse YAML: {exc}")
			continue

		jobs = doc.get("jobs", {}) if isinstance(doc, dict) else {}
		if not isinstance(jobs, dict):
			continue

		for job_name, job in jobs.items():
			if not isinstance(job, dict):
				continue

			for idx, step in enumerate(normalize_steps(job), start=1):
				if not isinstance(step, dict):
					continue
				step_name = str(step.get("name", f"{job_name}.step{idx}"))

				uses_value = step.get("uses")
				if isinstance(uses_value, str):
					check_uses(rel, step_name, uses_value.strip(), violations)

				run_value = step.get("run")
				if isinstance(run_value, str):
					check_run(rel, step_name, run_value, violations, curl_pipe_allowlist)

	if violations:
		print("Workflow policy violations:")
		for v in violations:
			print(f"- {v}")
		return 1

	print("Workflow policy checks passed.")
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
