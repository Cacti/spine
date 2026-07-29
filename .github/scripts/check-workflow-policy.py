#!/usr/bin/env python3
"""Enforce workflow hygiene policy on GitHub Actions files."""

from __future__ import annotations

import json
import re
import shlex
import sys
from pathlib import Path
from urllib.parse import urlparse

import yaml


PINNED_REF_RE = re.compile(r"^[0-9a-f]{40}$")
STRICT_LINE = "set -euo pipefail"
WORKFLOW_GLOB = ".github/workflows/*"
POLICY_CONFIG = ".github/workflow-policy.json"
PIPE_SHELL_COMMANDS = {"bash", "sh", "python", "python3", "perl", "ruby", "php", "node"}


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

	for line in run_value.splitlines():
		check_curl_pipeline(path, step_name, line, violations, curl_pipe_allowlist)


def shell_words(command: str) -> list[str]:
	try:
		return shlex.split(command, comments=True, posix=True)
	except ValueError:
		return []


def curl_urls(words: list[str]) -> list[str]:
	urls: list[str] = []
	skip_next = False
	for word in words[1:]:
		if skip_next:
			skip_next = False
			continue
		if word in {"-o", "--output", "-H", "--header", "-d", "--data", "--data-raw", "--data-binary"}:
			skip_next = True
			continue
		if word.startswith("-"):
			continue
		if word.startswith(("http://", "https://")):
			urls.append(word)
	return urls


def curl_urls_allowlisted(urls: list[str], allow_tokens: list[str]) -> bool:
	if not urls or not allow_tokens:
		return False

	for url in urls:
		parsed = urlparse(url)
		host = parsed.hostname or ""
		host_path = host + parsed.path
		netloc_path = parsed.netloc + parsed.path
		candidates = {url, parsed.netloc, host, host_path, netloc_path}
		if any(token in candidates for token in allow_tokens):
			return True

	return False


def check_curl_pipeline(path: str, step_name: str, line: str, violations: list[str], curl_pipe_allowlist: dict[str, list[str]]) -> None:
	stages = [stage.strip() for stage in line.split("|")]
	for idx, stage in enumerate(stages[:-1]):
		words = shell_words(stage)
		if not words or Path(words[0]).name != "curl":
			continue

		for next_stage in stages[idx + 1:]:
			next_words = shell_words(next_stage)
			if next_words and Path(next_words[0]).name in PIPE_SHELL_COMMANDS:
				allow_tokens = curl_pipe_allowlist.get(path, [])
				if not curl_urls_allowlisted(curl_urls(words), allow_tokens):
					violations.append(f"{path}:{step_name}: curl pipeline to interpreter is not allowlisted")
				return


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

		if not isinstance(doc, dict):
			violations.append(f"{rel}: top-level YAML must be a mapping")
			continue

		jobs = doc.get("jobs", {})
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
