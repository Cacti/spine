# Platform Idioms

This document defines platform-specific implementation idioms used by Spine.
It is intended to keep behavior, error handling, and build posture consistent
across supported operating systems.

## Linux

- Treat Linux as the primary production target.
- Prefer strict compiler diagnostics and sanitizer-backed validation.
- Use POSIX feature macros via build system (`_POSIX_C_SOURCE`, `_DEFAULT_SOURCE`).
- Keep privilege model explicit (capabilities/setuid behavior for raw ICMP paths).

## Windows (MSYS2/MinGW)

- Prefer native Win32 process APIs for runtime behavior (`CreateProcessW`).
- Convert UTF-8 inputs to UTF-16 at API boundaries.
- Use PID-based process lifecycle (`OpenProcess` in wait/terminate paths).
- Treat custom `envp` blocks as unsupported unless packed environment-block support
  is explicitly implemented.
- Keep WinSock error semantics explicit (`WSA*` error domain).

## macOS

- Keep tooling paths compatible with both Homebrew and MacPorts.
- Preserve BSD socket behavior and avoid Linux-only assumptions.
- Maintain `CMAKE_PREFIX_PATH` guidance for OpenSSL/MySQL/Net-SNMP discovery.

## FreeBSD

- Preserve BSD header/type expectations and test in CI VM lanes.
- Keep package naming and docs aligned with `pkg` conventions.
- Avoid GNU-only build/script assumptions unless guarded.

## Solaris

- Use explicit portability macros where required
  (`_POSIX_PTHREAD_SEMANTICS`, `_XOPEN_SOURCE`, `__EXTENSIONS__`).
- Treat package/discovery paths as best-effort (`/opt/csw`, system paths).
- Keep behavior conservative and avoid unverified Linux/glibc assumptions.

## AIX

- Use explicit portability macros where required (`_ALL_SOURCE`, `_XOPEN_SOURCE`).
- Treat `/opt/freeware` as a first-class dependency prefix.
- Keep shell/build logic POSIX-compatible and avoid GNU-specific shortcuts.

## Security and Execution

- Avoid shell execution for untrusted command text.
- Spine relies on the script-trust model documented in `SECURITY.md`: the
  Cacti application is the trust boundary, and command strings stored in the
  database are considered operator-controlled. Spine does not block shell
  metacharacters at spawn time; that responsibility sits with the Cacti
  front end where the script is admitted.
- Child environments are scrubbed of LD_*, DYLD_*, BASH_ENV, and ENV before
  spawn so a tampered parent environment cannot hijack the dynamic linker or
  shell startup.
- Keep process-spawn APIs and argument handling deterministic and test-covered.
