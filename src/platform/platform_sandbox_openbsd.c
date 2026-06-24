/* OpenBSD pledge(2) and unveil(2) live in <unistd.h> gated on
 * __BSD_VISIBLE. Under strict _POSIX_C_SOURCE the macro defaults to 0;
 * set it here before any system header runs so <unistd.h> declares them. */
#if defined(__OpenBSD__) && !defined(__BSD_VISIBLE)
#define __BSD_VISIBLE 1
#endif

#include "platform_sandbox.h"

#ifdef __OpenBSD__

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

/* unveil() narrows the filesystem view; pledge() narrows the syscall set.
 * Both sealed once spine_sandbox_restrict() returns. */

void spine_sandbox_unveil_paths(const char *log_path, const char *pid_path, const char *scripts_dir) {
	if (log_path != NULL && log_path[0] != '\0') {
		if (unveil(log_path, "cw") == -1 && errno != ENOENT) {
			fprintf(stderr, "WARNING: unveil(log) failed: %s\n", strerror(errno));
		}
	}
	if (pid_path != NULL && pid_path[0] != '\0') {
		if (unveil(pid_path, "cw") == -1 && errno != ENOENT) {
			fprintf(stderr, "WARNING: unveil(pid) failed: %s\n", strerror(errno));
		}
	}
	if (scripts_dir != NULL && scripts_dir[0] != '\0') {
		if (unveil(scripts_dir, "rx") == -1 && errno != ENOENT) {
			fprintf(stderr, "WARNING: unveil(scripts) failed: %s\n", strerror(errno));
		}
	}
	/* Config files still read by dependent libs (resolv.conf, hosts, ssl certs). */
	(void) unveil("/etc/resolv.conf", "r");
	(void) unveil("/etc/hosts", "r");
	(void) unveil("/etc/ssl", "r");
	(void) unveil("/etc/spine.conf", "r");

	/* Seal the path set. No further unveil() calls allowed after this. */
	if (unveil(NULL, NULL) == -1) {
		fprintf(stderr, "WARNING: unveil(NULL) seal failed: %s\n", strerror(errno));
	}
}

void spine_sandbox_restrict(void) {
	/* Promise set rationale:
	 *   stdio    -- read/write/close on open fds, signals, basic syscalls
	 *   rpath    -- open() for reading (config, library data)
	 *   wpath    -- open() for writing (log rotation, PID file)
	 *   cpath    -- creat() (log, PID)
	 *   inet     -- socket()/connect()/bind() on AF_INET*
	 *   dns      -- getaddrinfo() resolver traffic
	 *   proc     -- fork() for script exec path
	 *   exec     -- execve() of poll scripts
	 *   getpw    -- getpwuid() for user lookup via drop_root
	 */
	/* The second argument is execpromises: the promise set handed to any
	 * program spine exec()s. Dropping wpath/cpath/getpw there means a
	 * compromised poll script cannot write files, create directories, or
	 * read the password database, while keeping the read + network + spawn
	 * promises that legitimate check scripts rely on. */
	if (pledge("stdio rpath wpath cpath inet dns proc exec getpw",
	           "stdio rpath inet dns proc exec") == -1) {
		/* Non-fatal: keep running with unsandboxed privileges. */
		fprintf(stderr, "WARNING: pledge() failed: %s\n", strerror(errno));
	}
}

#endif
