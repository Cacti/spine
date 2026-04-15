#include "platform_sandbox.h"

#ifdef __linux__

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/prctl.h>

/* Linux has no path-level primitive equivalent to OpenBSD unveil(). We rely
 * on systemd unit directives (ReadWritePaths, ProtectSystem, etc.) for
 * filesystem confinement, and apply PR_SET_NO_NEW_PRIVS + an optional
 * seccomp allowlist for syscall confinement. */

void spine_sandbox_unveil_paths(const char *log_path, const char *pid_path, const char *scripts_dir) {
	(void) log_path;
	(void) pid_path;
	(void) scripts_dir;
}

void spine_sandbox_restrict(void) {
	/* PR_SET_NO_NEW_PRIVS: a ptrace-proof flag that blocks execve() from
	 * regaining dropped capabilities through setuid binaries. Cheap,
	 * universally supported since 3.5, and required before any non-root
	 * seccomp filter anyway. */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
		fprintf(stderr, "WARNING: prctl(PR_SET_NO_NEW_PRIVS) failed: %s\n", strerror(errno));
	}

	/* A full seccomp-bpf allowlist is deferred. Spine's syscall surface is
	 * large (mysqlclient + libnetsnmp + libpthread + popen-style child exec)
	 * and mis-sizing the allowlist silently kills polls. A future change
	 * that builds the allowlist through libseccomp, exercises it under the
	 * integration suite, and ships behind SPINE_SECCOMP=1 belongs in its
	 * own review. */
}

#endif
