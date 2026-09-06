#!/usr/bin/env bash
# Shared assertions and TAP output for Spine's shell integration tests.
# shellcheck shell=bash

if [[ -n "${SPINE_TEST_HARNESS_LOADED:-}" ]]; then
	return 0
fi
readonly SPINE_TEST_HARNESS_LOADED=1

HARNESS_PASS=0
HARNESS_FAIL=0
HARNESS_ASSERTIONS=0
HARNESS_SUITE=${HARNESS_SUITE:-spine}
HARNESS_ARTIFACT_DIR=${SPINE_TEST_ARTIFACT_DIR:-}
HARNESS_TAP_FILE=

harness_init() {
	HARNESS_SUITE=$1
	HARNESS_PASS=0
	HARNESS_FAIL=0
	HARNESS_ASSERTIONS=0

	if [[ -n "$HARNESS_ARTIFACT_DIR" ]]; then
		mkdir -p "$HARNESS_ARTIFACT_DIR"
		HARNESS_TAP_FILE="$HARNESS_ARTIFACT_DIR/results.tap"
		printf 'TAP version 13\n' > "$HARNESS_TAP_FILE"
	fi
}

harness_tap_escape() {
	local message=$1
	message=${message//$'\n'/ }
	message=${message//$'\r'/ }
	printf '%s' "$message"
}

harness_record() {
	local status=$1
	shift
	local message=$*

	HARNESS_ASSERTIONS=$((HARNESS_ASSERTIONS + 1))
	if [[ "$status" == pass ]]; then
		HARNESS_PASS=$((HARNESS_PASS + 1))
		printf '  PASS: %s\n' "$message"
		if [[ -n "$HARNESS_TAP_FILE" ]]; then
			printf 'ok %d - %s\n' "$HARNESS_ASSERTIONS" \
				"$(harness_tap_escape "$message")" >> "$HARNESS_TAP_FILE"
		fi
	else
		HARNESS_FAIL=$((HARNESS_FAIL + 1))
		printf '  FAIL: %s\n' "$message" >&2
		if [[ -n "$HARNESS_TAP_FILE" ]]; then
			printf 'not ok %d - %s\n' "$HARNESS_ASSERTIONS" \
				"$(harness_tap_escape "$message")" >> "$HARNESS_TAP_FILE"
		fi
	fi
}

harness_pass() { harness_record pass "$@"; }
harness_fail() { harness_record fail "$@"; }

harness_assert_eq() {
	local expected=$1
	local actual=$2
	shift 2
	if [[ "$actual" == "$expected" ]]; then
		harness_pass "$* (got $actual)"
	else
		harness_fail "$* (expected $expected, got $actual)"
	fi
}

harness_assert_contains() {
	local value=$1
	local pattern=$2
	shift 2
	if grep -Eq "$pattern" <<< "$value"; then
		harness_pass "$*"
	else
		harness_fail "$* (pattern not found: $pattern)"
	fi
}

harness_assert_not_contains() {
	local value=$1
	local pattern=$2
	shift 2
	if grep -Eiq "$pattern" <<< "$value"; then
		harness_fail "$* (unexpected pattern: $pattern)"
	else
		harness_pass "$*"
	fi
}

harness_finish() {
	printf '\n=== %s: %d passed, %d failed ===\n' \
		"$HARNESS_SUITE" "$HARNESS_PASS" "$HARNESS_FAIL"

	if [[ -n "$HARNESS_TAP_FILE" ]]; then
		printf '1..%d\n' "$HARNESS_ASSERTIONS" >> "$HARNESS_TAP_FILE"
		printf 'TAP results: %s\n' "$HARNESS_TAP_FILE"
	fi

	if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
		{
			printf '### %s\n\n' "$HARNESS_SUITE"
			printf -- '- Passed: %d\n- Failed: %d\n' "$HARNESS_PASS" "$HARNESS_FAIL"
		} >> "$GITHUB_STEP_SUMMARY"
	fi

	[[ $HARNESS_FAIL -eq 0 ]]
}
