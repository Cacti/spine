#include "platform_sandbox.h"

/* Fallback stub for POSIX platforms without a native sandbox primitive
 * (macOS, Solaris, AIX, NetBSD, DragonFly, generic SysV). OpenBSD, Linux,
 * and FreeBSD compile their own translation units and exclude this one via
 * the preprocessor guards below. */
#if !defined(_WIN32) && !defined(__OpenBSD__) && !defined(__linux__) && !defined(__FreeBSD__)

void spine_sandbox_unveil_paths(const char *log_path, const char *pid_path, const char *scripts_dir) {
	(void) log_path;
	(void) pid_path;
	(void) scripts_dir;
}

void spine_sandbox_restrict(void) {
}

#endif
