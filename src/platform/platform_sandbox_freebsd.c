#include "platform_sandbox.h"

#ifdef __FreeBSD__

/* FreeBSD Capsicum works at fd level, not path level, and entering
 * capability mode is incompatible with spine's fork+execve child-exec path
 * (open() becomes illegal globally; every exec would need fexecve() with a
 * pre-opened directory fd). Landing cap_enter() blindly breaks poll script
 * execution.
 *
 * The correct Capsicum scope for spine is per-thread limiting on the SNMP
 * and PHP worker fds once the main thread finishes spawning children, or
 * dropping Capsicum onto the forked poll-script processes between fork()
 * and execve(). That work requires touching the child-spawn path in
 * nft_popen.c and the SNMP session code, and should be measured against
 * the existing integration matrix before shipping. Leaving the hook in
 * place as a documented no-op so future work has somewhere to land. */

void spine_sandbox_unveil_paths(const char *log_path, const char *pid_path, const char *scripts_dir) {
	(void) log_path;
	(void) pid_path;
	(void) scripts_dir;
}

void spine_sandbox_restrict(void) {
}

#endif
