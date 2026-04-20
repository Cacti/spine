# Dismissed Security Alerts

Audit trail for CodeQL / cppcheck alerts that were reviewed and
dismissed on the `feat/distro-test-matrix` branch (PR #535).

## Batch: cppcheck style notes (2026-04-13)

161 cppcheck NOTE-severity alerts were dismissed as "won't fix".

Breakdown by rule:

- `variableScope` (61): narrower-scope suggestions for locals that are
  used across branches. Not a correctness issue.
- `constVariablePointer` (29), `constVariable` (5), `constParameter` (1),
  `constParameterPointer` (3): recommendations to add `const`
  qualifiers. Stylistic only; the existing API surface is stable.
- `unusedStructMember` (19): struct fields reserved for future use or
  required by on-wire layouts.
- `unreadVariable` (17): locals that are written in one preprocessor
  branch and consumed in another; cppcheck does not fully follow the
  conditional compilation.
- `funcArgNamesDifferent` (8): declaration vs definition parameter
  name mismatches. No ABI impact.
- `unreachableCode` (5): `exit()` / `abort()` followed by cleanup
  guards used by the test harness on some paths. The extra statements
  are defensive.
- `redundantAssignment` (4): variables reinitialised in distinct
  preprocessor branches; see `unreadVariable`.
- `unusedVariable` (2), `shadowFunction` (2), `knownConditionTrueFalse` (2),
  `redundantInitialization` (1), `duplicateBranch` (1),
  `CastAddressToIntegerAtReturn` (1): miscellaneous style findings
  inspected individually and judged non-security-relevant.

These do not represent security issues and are common in C99 code
that has to compile under both POSIX and Win32 with preprocessor
guards. Dismissed to reduce alert noise so real findings remain
visible.

## Individual warnings dismissed as false positives

- `#104`, `#105` (`invalidScanfFormatWidth_smaller`, `src/util.c:1172`):
  `sscanf(buff, "%15s %255s", p1, p2)` uses widths smaller than the
  1024-byte destination buffers on purpose to bound config-token
  length. cppcheck's heuristic flags width < destination as
  potentially unsafe; the reverse (width >= destination) is the bug
  pattern. Dismissed as inconclusive false positive.

## Individual errors dismissed as false positives

- `#181` (`ctuuninitvar`, `src/platform/platform_win.c:40`):
  cppcheck CTU analysis reports that the `out` parameter of
  `spine_platform_localtime` points at an uninitialised `now_time`.
  `out` is an output parameter: `localtime_s(out, when)` on Win32
  and `localtime_r(when, out)` on POSIX both write to `*out`. The
  caller's `struct tm now_time;` is intentionally left uninitialised
  because the function fills it. Dismissed as false positive.
