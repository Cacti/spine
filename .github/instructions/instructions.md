# GitHub Copilot Instructions for spine

spine is the high-performance C poller for Cacti. It is a multi-threaded
POSIX C17 program using pthreads, net-snmp, and libmariadb, built with
GNU autotools.

## Language and standard

- C17 with GNU extensions (`-std=gnu17`, set by `configure`). See
  `docs/adr/0001-c17-language-standard.md`.
- Keep variable scope narrow and initialize at definition. No VLAs.
- `_Static_assert` and `_Noreturn` are fine. Keep pthreads; do not use
  `<threads.h>` or C23 features.
- POSIX.1-2008 is the baseline. Do not use glibc extensions unless they
  already appear in the codebase.
- Retain each file’s license and contributor credits using SPDX notices.
  Keep module headers beside implementations; `include/spine/` is reserved
  for deliberately supported external interfaces.

## Build system

- `configure.ac` + `Makefile.am`. Run `./bootstrap` to regenerate.
- AC_PREREQ is 2.69. Do not add macros deprecated before autoconf 2.69
  (AC_C_CONST, AC_STRUCT_TM, RETSIGTYPE, etc.). AC_HEADER_TIME is used
  and must be kept because `src/internal/common.h` guards with TIME_WITH_SYS_TIME.
- `make -j$(nproc) CFLAGS="-Wall -Wextra"` must produce zero warnings.

## Code conventions

- Indentation: tabs (match existing files exactly).
- Function names: `snake_case`. Type names: `snake_case_t` for typedefs.
- Error paths: print to `SPINE_LOG` or `cacti_log`, then `return` or
  `exit`. Never silently swallow errors.
- Locking: acquire mutexes in a consistent order to avoid deadlock.
  Document the lock order in comments where it is not obvious.
- Memory: every `malloc` / `calloc` return must be checked immediately.
  Use checked `spine_snprintf` and `STRNCOPY` where their contracts fit.
  Check truncation and capacity explicitly; do not depend on Annex K.
- String buffers: declare length constants; do not use magic numbers for
  buffer sizes.

## SNMP

- Use net-snmp session API. Initialize with `snmp_sess_init` and always
  call `snmp_sess_close` on the session pointer.
- `SNMP_Clientaddr` binds the outgoing interface; respect it when
  opening sessions.
- OID arrays: always check `snmp_parse_oid` return value.

## Database

- Send SQL through the db_* wrappers in
  `src/database/sql.c`. Escape values with `db_escape` and check buffer
  bounds and database outcomes. No raw `mysql_query` calls in poller code.
- Connection flags: respect `DB_UseSSL` and the SSL key/cert/CA
  settings parsed from `spine.conf`.

## Configuration file

- `etc/spine.conf.dist` is the authoritative reference. When adding a new
  setting, add it to the header comment block AND as a commented example
  line in the settings section.
- Parse new keys in `src/config/file.c:read_spine_config()`. Add the field to
  `config_t` in `src/config/model.h`.

## Testing and CI

- When configuring CI, it SHOULD run at least: build (gcc+clang), cppcheck, flawfinder, and CodeQL.
- Before opening a PR, run
  `cppcheck --enable=all --std=c17 --library=scripts/cppcheck/spine.cfg src`
  locally and fix all errors (warnings are informational).
- flawfinder level-5 hits fail CI; lower levels are informational.

## Script and process execution design principles (do not regress)

These constraints exist because they were each violated once and caused a
measurable poller slowdown (PR #614, and a long-standing bug in 1.2.x's
`nft_pclose()`). Any change touching script or PHP Script Server execution
must preserve all three:

- **One shot, no EOF wait.** A script or PHP Script Server command gets
  exactly one read attempt within `script_timeout`. Never loop reading
  until EOF or read a second response after the first read (or timeout)
  completes. See `exec_poll()` in `src/poller/poller.c` and `php_read_result()` in
  `src/script/protocol.c`.
- **Never block the polling thread on `waitpid()`.** After a script's
  pipe is closed, reap with a single non-blocking `waitpid(..., WNOHANG)`
  and stop there. Do not spin/`usleep()`/retry waiting for the child to
  exit, and do not escalate SIGTERM/SIGKILL synchronously in the calling
  thread — hand off anything not immediately reaped to the async sweep
  (`AbandonedPids`/`nft_sweep_abandoned()` in `src/process/nft_popen.c`). This applies
  to both `nft_pclose()` and `php_close()`.
- **Script timeouts must go through `nft_popen()`/`nft_pchild()`.**
  Killing a timed-out script requires the real child pid, which is only
  tracked by `nft_popen()`. Do not reintroduce a native `popen()`/`pclose()`
  code path (`USING_TPOPEN`/`--enable-popen`) — it cannot expose a pid to
  kill on timeout and abandons the process/descriptor instead of
  terminating it.

`tests/regression/test_child_process_safety.sh` guards these invariants
structurally; keep it passing and extend it rather than relaxing it.

## Commits and PRs

- Conventional Commits: `fix(scope):`, `feat(scope):`, `build:`,
  `docs:`, `chore:`.
- DCO sign-off is required: `git commit -s`.
- One logical change per commit. Do not mix build fixes with logic
  changes.
- PR descriptions: state what changed, why, and what was tested.
  No AI-generated boilerplate.
- Add a `CHANGELOG` entry for every bug fix or feature under the
  current unreleased version header, in the existing
  `-issue#NNN: <summary>` / `-feature#NNN: <summary>` format. Use
  `-issue: <summary>` / `-feature: <summary>` (no number) only when no
  GitHub issue exists. Reference the issue the PR closes, not the PR
  number.
