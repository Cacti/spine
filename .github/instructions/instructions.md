# GitHub Copilot Instructions for spine

spine is the high-performance C poller for Cacti. It is a multi-threaded
POSIX C99 program using pthreads, net-snmp, and libmariadb, built with
GNU autotools.

## Language and standard

- C99. Mixed declarations and statements are allowed. No VLAs.
- POSIX.1-2008 is the baseline. Do not use glibc extensions unless they
  already appear in the codebase.
- All new files must include the LGPL-2.1 header block found in `spine.c`.

## Build system

- `configure.ac` + `Makefile.am`. Run `./bootstrap` to regenerate.
- AC_PREREQ is 2.69. Do not add macros deprecated before autoconf 2.69
  (AC_C_CONST, AC_STRUCT_TM, RETSIGTYPE, etc.). AC_HEADER_TIME is used
  and must be kept because common.h guards with TIME_WITH_SYS_TIME.
- `make -j$(nproc) CFLAGS="-Wall -Wextra"` must produce zero warnings.

## Code conventions

- Indentation: tabs (match existing files exactly).
- Function names: `snake_case`. Type names: `snake_case_t` for typedefs.
- Error paths: print to `SPINE_LOG` or `cacti_log`, then `return` or
  `exit`. Never silently swallow errors.
- Locking: acquire mutexes in a consistent order to avoid deadlock.
  Document the lock order in comments where it is not obvious.
- Memory: every `malloc` / `calloc` return must be checked immediately.
  Use `snprintf`, never `sprintf`. Use `strncat`/`strncpy` with explicit
  bounds.
- String buffers: declare length constants; do not use magic numbers for
  buffer sizes.
- Public APIs: prefer `const char *` for input-only string parameters.
  Document ownership expectations in function comments when transfer is not
  obvious.

## SNMP

- Use net-snmp session API. Initialize with `snmp_sess_init` and always
  call `snmp_sess_close` on the session pointer.
- `SNMP_Clientaddr` binds the outgoing interface; respect it when
  opening sessions.
- OID arrays: always check `snmp_parse_oid` return value.

## Database

- All SQL must use parameterized queries via the db_* wrappers in
  `sql.c`. No raw `mysql_query` calls in poller code.
- Connection flags: respect `DB_UseSSL` and the SSL key/cert/CA
  settings parsed from `spine.conf`.

## Configuration file

- `spine.conf.dist` is the authoritative reference. When adding a new
  setting, add it to the header comment block AND as a commented example
  line in the settings section.
- Parse new keys in `util.c:read_spine_config()`. Add the field to
  `config_struct` in `spine.h`.

## Testing and CI

- When configuring CI, it SHOULD run at least: build (gcc+clang), cppcheck, flawfinder, and CodeQL.
- Before opening a PR, run `cppcheck --enable=all --std=c11 *.c *.h`
  locally and fix all errors (warnings are informational).
- flawfinder level-5 hits fail CI; lower levels are informational.
- CI has a guardrail for newly introduced unsafe C APIs (`sprintf`, `strcpy`,
  `strcat`, `gets`, `vsprintf`) and fails closed on additions.

## Commits and PRs

- Conventional Commits: `fix(scope):`, `feat(scope):`, `build:`,
  `docs:`, `chore:`.
- DCO sign-off is required: `git commit -s`.
- One logical change per commit. Do not mix build fixes with logic
  changes.
- PR descriptions: state what changed, why, and what was tested.
  No AI-generated boilerplate.
