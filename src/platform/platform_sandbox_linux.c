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

#ifdef HAVE_LIBSECCOMP
#include <seccomp.h>
#endif

#ifdef HAVE_LANDLOCK
#include <linux/landlock.h>
#include <sys/syscall.h>
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
		"/tmp",      /* temp spools; most deployments need rw here */
		"/var/run",
		"/run",
		NULL,
	};
	for (int i = 0; ro_roots[i]; i++) {
		uint64_t mode = LANDLOCK_ACCESS_FS_READ_FILE
		              | LANDLOCK_ACCESS_FS_READ_DIR
		              | LANDLOCK_ACCESS_FS_EXECUTE;
		if (strcmp(ro_roots[i], "/tmp") == 0
		    || strcmp(ro_roots[i], "/var/run") == 0
		    || strcmp(ro_roots[i], "/run") == 0) {
			mode |= LANDLOCK_ACCESS_FS_WRITE_FILE
			      | LANDLOCK_ACCESS_FS_MAKE_REG
			      | LANDLOCK_ACCESS_FS_REMOVE_FILE;
		}
		if (add_path_rule(rs, ro_roots[i], mode) != 0) {
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
/* Syscall surface for a running spine poller. Derived from strace of a
 * local + remote poll cycle against MariaDB 10.11 and net-snmp 5.9 on
 * glibc 2.39. Missing a syscall here manifests as EPERM returns and
 * silent poll stalls, so anything plausibly on the hot path is included.
 *
 * Duplicates across platforms are harmless; seccomp_rule_add dedupes. */
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

	static const int allow[] = {
		/* I/O */
		SCMP_SYS(read), SCMP_SYS(write), SCMP_SYS(pread64), SCMP_SYS(pwrite64),
		SCMP_SYS(readv), SCMP_SYS(writev), SCMP_SYS(preadv), SCMP_SYS(pwritev),
		SCMP_SYS(preadv2), SCMP_SYS(pwritev2),
		SCMP_SYS(close), SCMP_SYS(close_range),
		SCMP_SYS(lseek), SCMP_SYS(dup), SCMP_SYS(dup2), SCMP_SYS(dup3),

		/* File descriptors / stat family */
		SCMP_SYS(open), SCMP_SYS(openat), SCMP_SYS(openat2),
		SCMP_SYS(fcntl), SCMP_SYS(fcntl64),
		SCMP_SYS(fstat), SCMP_SYS(fstat64),
		SCMP_SYS(stat), SCMP_SYS(stat64),
		SCMP_SYS(lstat), SCMP_SYS(lstat64),
		SCMP_SYS(newfstatat), SCMP_SYS(statx),
		SCMP_SYS(access), SCMP_SYS(faccessat), SCMP_SYS(faccessat2),
		SCMP_SYS(readlink), SCMP_SYS(readlinkat),
		SCMP_SYS(getdents), SCMP_SYS(getdents64),
		SCMP_SYS(getcwd), SCMP_SYS(chdir), SCMP_SYS(fchdir),
		SCMP_SYS(unlink), SCMP_SYS(unlinkat),
		SCMP_SYS(rename), SCMP_SYS(renameat), SCMP_SYS(renameat2),
		SCMP_SYS(mkdir), SCMP_SYS(mkdirat),
		SCMP_SYS(chmod), SCMP_SYS(fchmod), SCMP_SYS(fchmodat),
		SCMP_SYS(chown), SCMP_SYS(fchown), SCMP_SYS(fchownat), SCMP_SYS(lchown),
		SCMP_SYS(utimensat), SCMP_SYS(utimes), SCMP_SYS(futimesat),
		SCMP_SYS(umask),
		SCMP_SYS(flock), SCMP_SYS(fsync), SCMP_SYS(fdatasync),
		SCMP_SYS(truncate), SCMP_SYS(ftruncate),
		SCMP_SYS(sync_file_range), SCMP_SYS(fadvise64),
		SCMP_SYS(copy_file_range), SCMP_SYS(sendfile), SCMP_SYS(sendfile64),

		/* Pipes, polling, eventfd */
		SCMP_SYS(pipe), SCMP_SYS(pipe2),
		SCMP_SYS(select), SCMP_SYS(_newselect), SCMP_SYS(pselect6),
		SCMP_SYS(poll), SCMP_SYS(ppoll),
		SCMP_SYS(epoll_create), SCMP_SYS(epoll_create1),
		SCMP_SYS(epoll_wait), SCMP_SYS(epoll_pwait), SCMP_SYS(epoll_pwait2),
		SCMP_SYS(epoll_ctl),
		SCMP_SYS(eventfd), SCMP_SYS(eventfd2),
		SCMP_SYS(timerfd_create), SCMP_SYS(timerfd_settime), SCMP_SYS(timerfd_gettime),
		SCMP_SYS(signalfd), SCMP_SYS(signalfd4),

		/* Networking. net-snmp (UDP), MySQL (TCP/Unix), ICMP raw sockets. */
		SCMP_SYS(socket), SCMP_SYS(socketpair),
		SCMP_SYS(connect), SCMP_SYS(accept), SCMP_SYS(accept4),
		SCMP_SYS(bind), SCMP_SYS(listen),
		SCMP_SYS(shutdown),
		SCMP_SYS(sendto), SCMP_SYS(recvfrom),
		SCMP_SYS(sendmsg), SCMP_SYS(recvmsg), SCMP_SYS(sendmmsg), SCMP_SYS(recvmmsg),
		SCMP_SYS(getsockname), SCMP_SYS(getpeername),
		SCMP_SYS(setsockopt), SCMP_SYS(getsockopt),

		/* Memory */
		SCMP_SYS(brk),
		SCMP_SYS(mmap), SCMP_SYS(mmap2),
		SCMP_SYS(mremap), SCMP_SYS(munmap), SCMP_SYS(mprotect),
		SCMP_SYS(madvise), SCMP_SYS(mlock), SCMP_SYS(munlock),
		SCMP_SYS(mlockall), SCMP_SYS(munlockall),
		SCMP_SYS(mincore), SCMP_SYS(msync),

		/* Process / threading. spine forks PHP script servers and spawns
		 * pollers via posix_spawn(), which uses clone/execve underneath. */
		SCMP_SYS(clone), SCMP_SYS(clone3),
		SCMP_SYS(fork), SCMP_SYS(vfork),
		SCMP_SYS(execve), SCMP_SYS(execveat),
		SCMP_SYS(exit), SCMP_SYS(exit_group),
		SCMP_SYS(wait4), SCMP_SYS(waitid),
		SCMP_SYS(set_tid_address), SCMP_SYS(set_robust_list), SCMP_SYS(get_robust_list),
		SCMP_SYS(gettid), SCMP_SYS(getpid), SCMP_SYS(getppid), SCMP_SYS(getpgrp),
		SCMP_SYS(getpgid), SCMP_SYS(setpgid), SCMP_SYS(setsid),
		SCMP_SYS(getsid), SCMP_SYS(tgkill), SCMP_SYS(tkill), SCMP_SYS(kill),

		/* Identity */
		SCMP_SYS(getuid), SCMP_SYS(geteuid),
		SCMP_SYS(getgid), SCMP_SYS(getegid),
		SCMP_SYS(getgroups), SCMP_SYS(setgroups),
		SCMP_SYS(setresuid), SCMP_SYS(setresgid),
		SCMP_SYS(setreuid), SCMP_SYS(setregid),
		SCMP_SYS(setuid), SCMP_SYS(setgid),

		/* Signals */
		SCMP_SYS(rt_sigaction), SCMP_SYS(rt_sigprocmask),
		SCMP_SYS(rt_sigreturn), SCMP_SYS(rt_sigqueueinfo),
		SCMP_SYS(rt_sigsuspend), SCMP_SYS(rt_sigpending), SCMP_SYS(rt_sigtimedwait),
		SCMP_SYS(sigaltstack), SCMP_SYS(pause),

		/* Sync / futex */
		SCMP_SYS(futex), SCMP_SYS(futex_waitv),
		SCMP_SYS(sched_yield), SCMP_SYS(sched_getaffinity), SCMP_SYS(sched_setaffinity),
		SCMP_SYS(sched_getparam), SCMP_SYS(sched_getscheduler),

		/* Time */
		SCMP_SYS(clock_gettime), SCMP_SYS(clock_gettime64),
		SCMP_SYS(clock_getres), SCMP_SYS(clock_nanosleep), SCMP_SYS(clock_nanosleep_time64),
		SCMP_SYS(nanosleep), SCMP_SYS(gettimeofday), SCMP_SYS(time),

		/* System info / random */
		SCMP_SYS(uname), SCMP_SYS(sysinfo),
		SCMP_SYS(getrandom),
		SCMP_SYS(getrusage),

		/* Resource limits */
		SCMP_SYS(prlimit64), SCMP_SYS(getrlimit), SCMP_SYS(setrlimit),
		SCMP_SYS(getpriority), SCMP_SYS(setpriority),

		/* Misc control */
		SCMP_SYS(prctl), SCMP_SYS(arch_prctl),
		SCMP_SYS(ioctl),
		SCMP_SYS(restart_syscall),
	};

	for (size_t i = 0; i < sizeof(allow) / sizeof(allow[0]); i++) {
		/* A syscall number of -1 (__NR_SCMP_ERROR) means libseccomp has
		 * no mapping for this arch; skip silently so the cross-platform
		 * list above stays simple. */
		if (allow[i] < 0) continue;
		if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, allow[i], 0) != 0) {
			/* Non-fatal: a single missing syscall shouldn't drop the
			 * whole filter. Keep loading the rest. */
		}
	}

	/* Block ioctl(TIOCSTI) regardless of the generic ioctl allow above.
	 * TIOCSTI lets a process inject keystrokes into its controlling tty,
	 * a long-standing jailbreak vector if spine ever runs under a shared
	 * terminal (systemd's TTYPath= or an operator running it under sudo).
	 * libseccomp evaluates argument-scoped rules ahead of unqualified
	 * ALLOW rules for the same syscall, so this stays additive. */
	(void)seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ioctl), 1,
	                       SCMP_A1(SCMP_CMP_EQ, (scmp_datum_t)TIOCSTI));

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
