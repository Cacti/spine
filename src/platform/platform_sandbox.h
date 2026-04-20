#ifndef SPINE_PLATFORM_SANDBOX_H
#define SPINE_PLATFORM_SANDBOX_H

/* Per-platform sandbox primitives. Unsupported platforms compile to no-ops.
 *
 * Contract:
 *   spine_sandbox_unveil_paths() -- declare the filesystem paths spine will
 *     touch for the rest of its lifetime. Must be called before
 *     spine_sandbox_restrict() on platforms where the second call seals the
 *     path set (OpenBSD unveil).
 *
 *   spine_sandbox_restrict() -- drop privileges for the remainder of the
 *     process. Caller MUST have already opened every long-lived resource
 *     (DB connection, sockets, log file, PID file). On OpenBSD this calls
 *     pledge(); on Linux it applies PR_SET_NO_NEW_PRIVS (and, if built
 *     with libseccomp, a syscall allowlist).
 *
 * Any argument may be NULL; NULL paths are simply skipped.
 */
void spine_sandbox_unveil_paths(const char *log_path, const char *pid_path, const char *scripts_dir);
void spine_sandbox_restrict(void);

#endif
