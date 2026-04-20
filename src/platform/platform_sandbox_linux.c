#include "platform_sandbox.h"

#ifdef __linux__

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sched.h>

#ifdef HAVE_LIBSECCOMP
#include <seccomp.h>
#endif

#ifdef HAVE_LANDLOCK
#include <linux/landlock.h>
#include <sys/syscall.h>
#include <stdint.h>
#endif

/* Linux confinement layers:
 *
 *   1. PR_SET_NO_NEW_PRIVS       -- always applied. Blocks setuid-exec gain.
 *   2. Landlock                  -- optional. File-path confinement.
 *   3. seccomp-bpf allowlist     -- optional. Syscall surface restriction.
 *
 * Each layer is best-effort: a missing kernel feature or library at runtime
 * falls back to the looser layer rather than aborting spine. Operators can
 * force-disable individual layers with SPINE_NO_LANDLOCK / SPINE_NO_SECCOMP
 * environment variables (useful for debugging script servers that pull in
 * exotic syscalls).
 */

/* Paths unveiled at startup. Landlock stores them until spine_sandbox_restrict
 * seals the ruleset; seccomp has no path awareness but reads nothing here. */
static char g_log_path[4096];
static char g_pid_path[4096];
static char g_scripts_dir[4096];
static int  g_paths_captured = 0;

void spine_sandbox_unveil_paths(const char *log_path, const char *pid_path, const char *scripts_dir) {
	g_log_path[0] = '\0';
	g_pid_path[0] = '\0';
	g_scripts_dir[0] = '\0';

	if (log_path) {
		snprintf(g_log_path, sizeof(g_log_path), "%s", log_path);
	}
	if (pid_path) {
		snprintf(g_pid_path, sizeof(g_pid_path), "%s", pid_path);
	}
	if (scripts_dir) {
		snprintf(g_scripts_dir, sizeof(g_scripts_dir), "%s", scripts_dir);
	}

	g_paths_captured = 1;
}

#ifdef HAVE_LANDLOCK
/* Wrappers. glibc below 2.37 lacks a landlock_create_ruleset() shim; keep
 * the syscall numbers portable by going through syscall(2) directly. */
static inline int spine_landlock_create_ruleset(const struct landlock_ruleset_attr *attr,
                                                size_t size, __u32 flags) {
#ifdef SYS_landlock_create_ruleset
	return (int)syscall(SYS_landlock_create_ruleset, attr, size, flags);
#else
	(void)attr; (void)size; (void)flags;
	errno = ENOSYS;
	return -1;
#endif
}

static inline int spine_landlock_add_rule(int ruleset_fd, enum landlock_rule_type rule_type,
                                          const void *rule_attr, __u32 flags) {
#ifdef SYS_landlock_add_rule
	return (int)syscall(SYS_landlock_add_rule, ruleset_fd, rule_type, rule_attr, flags);
#else
	(void)ruleset_fd; (void)rule_type; (void)rule_attr; (void)flags;
	errno = ENOSYS;
	return -1;
#endif
}

static inline int spine_landlock_restrict_self(int ruleset_fd, __u32 flags) {
#ifdef SYS_landlock_restrict_self
	return (int)syscall(SYS_landlock_restrict_self, ruleset_fd, flags);
#else
	(void)ruleset_fd; (void)flags;
	errno = ENOSYS;
	return -1;
#endif
}

/* Best-effort parent-directory derivation for single-file unveils. */
static void path_dirname(const char *in, char *out, size_t out_sz) {
	if (!in || !*in) { out[0] = '\0'; return; }
	const char *slash = strrchr(in, '/');
	if (!slash) { snprintf(out, out_sz, "."); return; }
	size_t n = (size_t)(slash - in);
	if (n == 0) { snprintf(out, out_sz, "/"); return; }
	if (n >= out_sz) n = out_sz - 1;
	memcpy(out, in, n);
	out[n] = '\0';
}

static int add_path_rule(int rs, const char *path, uint64_t allowed) {
	if (!path || !*path) return 0;

	int fd = open(path, O_PATH | O_CLOEXEC);
	if (fd < 0) {
		/* A missing log path is normal on first boot; skip silently so
		 * the caller isn't forced to race mkdir vs sandbox init. */
		if (errno == ENOENT) return 0;
		return -1;
	}

	struct landlock_path_beneath_attr beneath = {
		.allowed_access = allowed,
		.parent_fd = fd,
	};

	int rc = spine_landlock_add_rule(rs, LANDLOCK_RULE_PATH_BENEATH, &beneath, 0);
	int saved_errno = errno;
	close(fd);
	errno = saved_errno;
	return rc;
}

static int apply_landlock(void) {
	if (getenv("SPINE_NO_LANDLOCK")) return 0;

	/* ABI v1: covers READ_FILE, WRITE_FILE, EXECUTE, and path-level
	 * creation flags. ABI v2 adds REFER; v3 adds TRUNCATE. We request
	 * v1 features only so the ruleset loads on any 5.13+ kernel. */
	struct landlock_ruleset_attr attr = {
		.handled_access_fs =
			LANDLOCK_ACCESS_FS_EXECUTE
			| LANDLOCK_ACCESS_FS_WRITE_FILE
			| LANDLOCK_ACCESS_FS_READ_FILE
			| LANDLOCK_ACCESS_FS_READ_DIR
			| LANDLOCK_ACCESS_FS_REMOVE_DIR
			| LANDLOCK_ACCESS_FS_REMOVE_FILE
			| LANDLOCK_ACCESS_FS_MAKE_CHAR
			| LANDLOCK_ACCESS_FS_MAKE_DIR
			| LANDLOCK_ACCESS_FS_MAKE_REG
			| LANDLOCK_ACCESS_FS_MAKE_SOCK
			| LANDLOCK_ACCESS_FS_MAKE_FIFO
			| LANDLOCK_ACCESS_FS_MAKE_BLOCK
			| LANDLOCK_ACCESS_FS_MAKE_SYM,
	};

	int rs = spine_landlock_create_ruleset(&attr, sizeof(attr), 0);
	if (rs < 0) {
		/* ENOSYS on kernels without landlock is expected. EOPNOTSUPP
		 * happens when landlock is compiled in but disabled via
		 * lsm= boot param. Treat both as a silent skip. */
		if (errno == ENOSYS || errno == EOPNOTSUPP) return 0;
		return -1;
	}

	/* Log directory: read-write for the log file. Most deployments rotate
	 * the log so the directory needs WRITE_FILE + MAKE_REG, not the log
	 * file alone. */
	char dir[4096];
	if (g_log_path[0]) {
		path_dirname(g_log_path, dir, sizeof(dir));
		if (add_path_rule(rs, dir,
		                  LANDLOCK_ACCESS_FS_READ_FILE
		                  | LANDLOCK_ACCESS_FS_WRITE_FILE
		                  | LANDLOCK_ACCESS_FS_READ_DIR
		                  | LANDLOCK_ACCESS_FS_MAKE_REG
		                  | LANDLOCK_ACCESS_FS_REMOVE_FILE) != 0) {
			close(rs);
			return -1;
		}
	}

	if (g_pid_path[0]) {
		path_dirname(g_pid_path, dir, sizeof(dir));
		if (add_path_rule(rs, dir,
		                  LANDLOCK_ACCESS_FS_READ_FILE
		                  | LANDLOCK_ACCESS_FS_WRITE_FILE
		                  | LANDLOCK_ACCESS_FS_READ_DIR
		                  | LANDLOCK_ACCESS_FS_MAKE_REG
		                  | LANDLOCK_ACCESS_FS_REMOVE_FILE) != 0) {
			close(rs);
			return -1;
		}
	}

	/* Scripts directory: execute + read (poller scripts read templates). */
	if (g_scripts_dir[0]) {
		if (add_path_rule(rs, g_scripts_dir,
		                  LANDLOCK_ACCESS_FS_READ_FILE
		                  | LANDLOCK_ACCESS_FS_READ_DIR
		                  | LANDLOCK_ACCESS_FS_EXECUTE) != 0) {
			close(rs);
			return -1;
		}
	}

	/* Common read-only system paths required by the loader, resolver,
	 * and CA trust store. Missing paths are skipped by add_path_rule. */
	static const char *ro_roots[] = {
		"/etc",
		"/usr",
		"/lib",
		"/lib64",
		"/bin",
		"/sbin",
		"/proc",     /* getrandom fallback, uuid, self/maps for libc */
		"/sys",      /* netsnmp reads /sys/class/net */
		"/dev",      /* urandom, null */
		NULL,
	};
	for (int i = 0; ro_roots[i]; i++) {
		uint64_t mode = LANDLOCK_ACCESS_FS_READ_FILE
		              | LANDLOCK_ACCESS_FS_READ_DIR
		              | LANDLOCK_ACCESS_FS_EXECUTE;
		if (add_path_rule(rs, ro_roots[i], mode) != 0) {
			close(rs);
			return -1;
		}
	}

	/* Writable scratch/runtime dirs scoped to spine's own prefix. A
	 * previous revision allowed the bare /tmp, /var/run, and /run
	 * roots; that widened the blast radius to every other daemon
	 * sharing those trees (sshd auth spools, postgres socket lock,
	 * systemd notify sockets). mkdir() is best-effort with 0700 so
	 * the directory exists before landlock seals the ruleset: a
	 * missing directory silently drops the rule via add_path_rule's
	 * ENOENT branch, which would leave spine unable to write its
	 * pid / temp files. */
	static const char *rw_roots[] = {
		"/tmp/spine",
		"/run/spine",
		"/var/run/spine",
		NULL,
	};
	for (int i = 0; rw_roots[i]; i++) {
		(void)mkdir(rw_roots[i], 0700);
		uint64_t mode = LANDLOCK_ACCESS_FS_READ_FILE
		              | LANDLOCK_ACCESS_FS_READ_DIR
		              | LANDLOCK_ACCESS_FS_WRITE_FILE
		              | LANDLOCK_ACCESS_FS_MAKE_REG
		              | LANDLOCK_ACCESS_FS_REMOVE_FILE;
		if (add_path_rule(rs, rw_roots[i], mode) != 0) {
			close(rs);
			return -1;
		}
	}

	/* PR_SET_NO_NEW_PRIVS is a hard prerequisite for landlock_restrict_self
	 * unless CAP_SYS_ADMIN is held. Spine drops caps before this point,
	 * so the prctl is mandatory. */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
		close(rs);
		return -1;
	}

	int rc = spine_landlock_restrict_self(rs, 0);
	int saved_errno = errno;
	close(rs);
	errno = saved_errno;
	return rc;
}
#endif /* HAVE_LANDLOCK */

#ifdef HAVE_LIBSECCOMP
static int seccomp_add_allowlist_by_name(scmp_filter_ctx ctx, const char *const *names, size_t count) {
	for (size_t i = 0; i < count; i++) {
		int nr = seccomp_syscall_resolve_name(names[i]);
		if (nr == __NR_SCMP_ERROR) continue;
		(void)seccomp_rule_add(ctx, SCMP_ACT_ALLOW, nr, 0);
	}
	return 0;
}

static int seccomp_resolve_nr(const char *name) {
	return seccomp_syscall_resolve_name(name);
}

/* Syscall surface for a running spine poller. Derived from strace of a
 * local + remote poll cycle against MariaDB 10.11 and net-snmp 5.9 on
 * glibc 2.39. Missing a syscall here manifests as EPERM returns and
 * silent poll stalls, so anything plausibly on the hot path is included.
 *
 * Duplicates across platforms are harmless; seccomp_rule_add dedupes.
 *
 * Policy is data-driven by syscall name to avoid compile-time dependence on
 * libc/libseccomp __SNR_* macro coverage across distro matrices. */
static int apply_seccomp(void) {
	if (getenv("SPINE_NO_SECCOMP")) return 0;

	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ERRNO(EPERM));
	if (!ctx) return -1;

	/* Apply the filter to every existing thread, not just the caller. By
	 * the time the sandbox activates spine has already spawned poller
	 * workers; without TSYNC they would keep running without seccomp. */
	(void)seccomp_attr_set(ctx, SCMP_FLTATR_CTL_TSYNC, 1);

	/* On x86_64, ia32 and x32 personalities share the kernel syscall entry
	 * and can reach spine's address space through the vsyscall page and
	 * 32-bit-aware loaders. Adding both architectures makes the allowlist
	 * cover those entry points. EEXIST on a system already matching the
	 * current arch is benign; libseccomp returns -EEXIST in that case. */
#if defined(__x86_64__)
	(void)seccomp_arch_add(ctx, SCMP_ARCH_X86);
	(void)seccomp_arch_add(ctx, SCMP_ARCH_X32);
#endif

	static const char *const allow[] = {
		/* I/O */
		"read", "write", "pread64", "pwrite64",
		"readv", "writev", "preadv", "pwritev",
		"preadv2", "pwritev2",
		"close", "close_range",
		"lseek", "dup", "dup2", "dup3",

		/* File descriptors / stat family */
		"open", "openat",
		"fcntl", "fcntl64",
		"fstat", "fstat64",
		"stat", "stat64",
		"lstat", "lstat64",
		"newfstatat", "statx",
		"access", "faccessat", "faccessat2",
		"readlink", "readlinkat", // flawfinder: ignore
		"getdents", "getdents64",
		"getcwd", "chdir", "fchdir",
		"unlink", "unlinkat",
		"rename", "renameat", "renameat2",
		"mkdir", "mkdirat",
		"chmod", "fchmod", "fchmodat", // flawfinder: ignore
		"chown", "fchown", "fchownat", "lchown", // flawfinder: ignore
		"utimensat", "utimes", "futimesat",
		"umask",
		"flock", "fsync", "fdatasync",
		"truncate", "ftruncate",
		"sync_file_range", "fadvise64",
		"copy_file_range", "sendfile", "sendfile64",

		/* Pipes, polling, eventfd */
		"pipe", "pipe2",
		"select", "_newselect", "pselect6",
		"poll", "ppoll",
		"epoll_create", "epoll_create1",
		"epoll_wait", "epoll_pwait",
		"epoll_ctl",
		"eventfd", "eventfd2",
		"timerfd_create", "timerfd_settime", "timerfd_gettime",
		"signalfd", "signalfd4",

		/* Networking. net-snmp (UDP), MySQL (TCP/Unix), ICMP raw sockets. */
		"socket", "socketpair",
		"connect", "accept", "accept4",
		"bind", "listen",
		"shutdown",
		"sendto", "recvfrom",
		"sendmsg", "recvmsg", "sendmmsg", "recvmmsg",
		"getsockname", "getpeername",
		"setsockopt", "getsockopt",

		/* Memory */
		"brk",
		"mmap", "mmap2",
		"mremap", "munmap", "mprotect",
		"madvise", "mlock", "munlock",
		"mlockall", "munlockall",
		"mincore", "msync",

		/* Process / threading. spine forks PHP script servers and spawns
		 * pollers via posix_spawn(), which uses clone/execve underneath.
		 * clone3 is intentionally omitted: its flags argument is inside
		 * a user-space struct the filter cannot inspect, so we deny it
		 * outright below and rely on glibc falling back to clone() on
		 * kernels that offer both. */
		"clone",
		"fork", "vfork",
		"execve", "execveat",
		"exit", "exit_group",
		"wait4", "waitid",
		"set_tid_address", "set_robust_list", "get_robust_list",
		"gettid", "getpid", "getppid", "getpgrp",
		"getpgid", "setpgid", "setsid",
		"getsid", "tgkill", "tkill", "kill",

		/* Identity */
		"getuid", "geteuid",
		"getgid", "getegid",
		"getgroups", "setgroups",
		"setresuid", "setresgid",
		"setreuid", "setregid",
		"setuid", "setgid",

		/* Signals */
		"rt_sigaction", "rt_sigprocmask",
		"rt_sigreturn", "rt_sigqueueinfo",
		"rt_sigsuspend", "rt_sigpending", "rt_sigtimedwait",
		"sigaltstack", "pause",

		/* Sync / futex */
		"futex",
		"sched_yield", "sched_getaffinity", "sched_setaffinity",
		"sched_getparam", "sched_getscheduler",

		/* Time */
		"clock_gettime", "clock_gettime64",
		"clock_getres", "clock_nanosleep", "clock_nanosleep_time64",
		"nanosleep", "gettimeofday", "time",

		/* System info / random */
		"uname", "sysinfo",
		"getrandom",
		"getrusage",

		/* Resource limits */
		"prlimit64", "getrlimit", "setrlimit",
		"getpriority", "setpriority",

		/* Misc control. prctl is allowed broadly; a targeted deny rule
		 * below blocks only PR_SET_DUMPABLE with arg1 != 0 (the
		 * specific op a compromised worker would use to re-enable
		 * core dumps). Allowing prctl generally means third-party
		 * libraries - glibc NSS, malloc implementations, net-snmp,
		 * mariadb-connector - keep initialising cleanly instead of
		 * hitting EPERM on common lifecycle calls. */
		"prctl", "arch_prctl",
		"ioctl",
		"restart_syscall",
	};

	(void)seccomp_add_allowlist_by_name(ctx, allow, sizeof(allow) / sizeof(allow[0]));

	/* Optional newer syscalls. Some distro/libseccomp combinations ship
	 * older syscall tables. Resolve by name and allow when present. */
	static const char *const optional_allow[] = {
		"openat2",
		"epoll_pwait2",
		"futex_waitv",
	};
	(void)seccomp_add_allowlist_by_name(ctx, optional_allow, sizeof(optional_allow) / sizeof(optional_allow[0]));

	const int ioctl_nr = seccomp_resolve_nr("ioctl");
	const int clone_nr = seccomp_resolve_nr("clone");
	const int clone3_nr = seccomp_resolve_nr("clone3");

	/* Block ioctl(TIOCSTI) regardless of the generic ioctl allow above.
	 * TIOCSTI lets a process inject keystrokes into its controlling tty,
	 * a long-standing jailbreak vector if spine ever runs under a shared
	 * terminal (systemd's TTYPath= or an operator running it under sudo).
	 * libseccomp evaluates argument-scoped rules ahead of unqualified
	 * ALLOW rules for the same syscall, so this stays additive. */
	if (ioctl_nr != __NR_SCMP_ERROR) {
		(void)seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), ioctl_nr, 1,
		                       SCMP_A1(SCMP_CMP_EQ, (scmp_datum_t)TIOCSTI));
	}

	/* Block clone(CLONE_NEWUSER): user namespaces let an unprivileged
	 * process acquire CAP_SYS_ADMIN inside the new ns, and spine never
	 * needs one. The SCMP_CMP_MASKED_EQ check matches any clone() whose
	 * flags include CLONE_NEWUSER, regardless of other bits set. */
	if (clone_nr != __NR_SCMP_ERROR) {
		(void)seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), clone_nr, 1,
		                       SCMP_A0(SCMP_CMP_MASKED_EQ,
		                               (scmp_datum_t)CLONE_NEWUSER,
		                               (scmp_datum_t)CLONE_NEWUSER));
	}

	/* clone3 takes its flags inside a user-space struct that bpf cannot
	 * dereference, so we cannot do a masked_eq on CLONE_NEWUSER there.
	 * Deny the whole syscall: glibc 2.34+ probes for clone3 at runtime
	 * and falls back to clone on ENOSYS. This is a measurable slowdown
	 * for processes that clone() in a hot loop; spine does not. */
	if (clone3_nr != __NR_SCMP_ERROR) {
		(void)seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), clone3_nr, 0);
	}

	/* Block the one prctl op we care about: PR_SET_DUMPABLE with a
	 * non-zero arg1 would re-enable core dumps for a compromised
	 * worker and let an attacker harvest credentials via SIGSEGV.
	 * Setting dumpable to 0 (the initial seal) and every other prctl
	 * op pass through via the blanket allowlist above, so third-party
	 * libraries' benign prctl calls (PR_SET_PTRACER, PR_SET_VMA,
	 * PR_GET_SECCOMP, PR_SET_PDEATHSIG, etc.) keep working. */
	const int prctl_nr = seccomp_resolve_nr("prctl");
	if (prctl_nr != __NR_SCMP_ERROR) {
		(void)seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), prctl_nr, 2,
		                       SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t)PR_SET_DUMPABLE),
		                       SCMP_A1(SCMP_CMP_NE, (scmp_datum_t)0));
	}

	int rc = seccomp_load(ctx);
	seccomp_release(ctx);
	return rc;
}
#endif /* HAVE_LIBSECCOMP */

void spine_sandbox_restrict(void) {
	/* PR_SET_NO_NEW_PRIVS: mandatory precondition for landlock_restrict_self
	 * and for any non-root seccomp filter. Cheap and universally supported
	 * since 3.5. */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
		fprintf(stderr, "WARNING: prctl(PR_SET_NO_NEW_PRIVS) failed: %s\n", strerror(errno));
	}

	/* PR_SET_DUMPABLE = 0 prevents ptrace attach by non-CAP_SYS_PTRACE
	 * processes and suppresses core dump generation. Database credentials
	 * live in process memory for spine's lifetime; denying ptrace closes
	 * the most common credential-theft path on a compromised host. */
	if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == -1) {
		fprintf(stderr, "WARNING: prctl(PR_SET_DUMPABLE) failed: %s\n", strerror(errno));
	}

#ifdef HAVE_LANDLOCK
	if (apply_landlock() != 0) {
		fprintf(stderr, "WARNING: landlock_restrict_self failed: %s\n", strerror(errno));
	}
#endif

#ifdef HAVE_LIBSECCOMP
	if (apply_seccomp() != 0) {
		fprintf(stderr, "WARNING: seccomp filter load failed: %s\n", strerror(errno));
	}
#endif

	(void)g_paths_captured;
}

#endif /* __linux__ */
