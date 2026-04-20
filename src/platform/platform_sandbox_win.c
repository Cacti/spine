#include "platform_sandbox.h"

/* Windows has no pledge/unveil analogue. Process hardening on Windows is
 * handled separately by the Job Object created in platform_win.c (which
 * bounds child-process lifetime, not syscalls). */
#ifdef _WIN32

void spine_sandbox_unveil_paths(const char *log_path, const char *pid_path, const char *scripts_dir) {
	(void) log_path;
	(void) pid_path;
	(void) scripts_dir;
}

void spine_sandbox_restrict(void) {
}

#endif
