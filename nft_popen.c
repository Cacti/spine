/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU General Public License             |
 | as published by the Free Software Foundation; either version 2          |
 | of the License, or (at your option) any later version.                  |
 |                                                                         |
 | This program is distributed in the hope that it will be useful,         |
 | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
 | GNU General Public License for more details.                            |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDtool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
 | This code is designed, written, and maintained by the Cacti Group. See  |
 | about.php and/or the AUTHORS file for specific developer information.   |
 +-------------------------------------------------------------------------+
 | http://www.cacti.net/                                                   |
 +-------------------------------------------------------------------------+
*/

/*******************************************************************************
 ex: set tabstop=4 shiftwidth=4 autoindent:
 * (C) Xenadyne Inc. 2002.	All Rights Reserved
 *
 * Permission to use, copy, modify and distribute this software for
 * any purpose and without fee is hereby granted, provided that the
 * above copyright notice appears in all copies. Also note the
 * University of California copyright below.
 *
 * XENADYNE INC DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.
 * IN NO EVENT SHALL XENADYNE BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM THE
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * File: nft_popen.c
 *
 * Description: A thread-safe replacement for popen()/pclose().
 *
 * This is a thread-safe variant of popen that does unbuffered IO, to
 * avoid running afoul of Solaris's inability to fdopen when fd > 255.
 *
 *******************************************************************************
 */

/*
 * Copyright (c) 1988, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software written by Ken Arnold and
 * published in UNIX Review, Vol. 6, No. 8.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "common.h"
#include "spine.h"
#include <spawn.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/wait.h>

/* An instance of this struct is created for each popen() fd. */
static struct pid
{
    struct pid *next;
    int		fd;
    pid_t	pid;
} * PidList;

/* Serialize access to PidList. */
static pthread_mutex_t ListMutex = PTHREAD_MUTEX_INITIALIZER;

/* Children nft_pclose() gave up waiting for. Nothing else in spine reaps: there
   is no SIGCHLD handler and no waitpid(-1), so a child dropped here would stay
   a zombie for the daemon's lifetime and accumulate once per affected script
   per cycle against RLIMIT_NPROC. SA_NOCLDWAIT would fix the leak but auto-reap
   every child, and spine reads exit status to tell a failed script from a silent
   one, so the pids are parked here and swept with WNOHANG instead. Bounded: past
   the cap the pid is logged and dropped, because an unbounded list trades a pid
   leak for a memory leak. */
static pid_t	AbandonedPids[NFT_ABANDONED_MAX];
static int	AbandonedCount;

static void	close_cleanup(void *);
static void	nft_sweep_abandoned(void);
static struct pid *pid_list_close_and_take(int);
#ifdef SPINE_NFT_PCLOSE_TESTING
extern void nft_abandon_parked_test_hook(void);
#endif

static void nft_pclose_abandon(pid_t pid, const char *reason,
	int *cancel_held, int *cancel_state) {
	if (!*cancel_held) {
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, cancel_state);
		*cancel_held = TRUE;
	}
	nft_abandon_child(pid, reason);
}

/* nft_pclose() must not block a poller thread indefinitely. Give a child the
 * configured script timeout to finish naturally after stdout closes, then use
 * the same TERM -> grace -> KILL policy as the PHP script-server shutdown. */
#define NFT_PCLOSE_REAP_USEC 50000
#define NFT_PCLOSE_SPIN_USEC 200
#define NFT_PCLOSE_SPIN_ATTEMPTS 10
#define NFT_PCLOSE_MAX_GRACE_SECONDS 5
#ifndef SOLAR_THREAD
#define NFT_PCLOSE_ATTEMPTS_PER_SEC 20
#define NFT_PCLOSE_SIGNAL_ATTEMPTS 30
#else
#define NFT_PCLOSE_ATTEMPTS_PER_SEC 1
#define NFT_PCLOSE_SIGNAL_ATTEMPTS 2
#endif

static int nft_pclose_grace_attempts(void) {
	int seconds = set.script_timeout;
	int interval_ceiling;
	#ifndef SOLAR_THREAD
	int max_seconds;
	#endif

	if (seconds < 1) seconds = 1;
	/* The script already received its full runtime budget before pclose. This
	 * is only a short post-output cleanup grace: never consume more than a
	 * tenth of the polling interval, and never exceed five seconds. A zero
	 * interval means Cacti's default interval, for which the absolute ceiling
	 * remains the conservative bound. */
	interval_ceiling = set.poller_interval > 0 ? set.poller_interval / 10 :
		NFT_PCLOSE_MAX_GRACE_SECONDS;
	if (interval_ceiling < 1) interval_ceiling = 1;
	if (interval_ceiling > NFT_PCLOSE_MAX_GRACE_SECONDS)
		interval_ceiling = NFT_PCLOSE_MAX_GRACE_SECONDS;
	if (seconds > interval_ceiling) seconds = interval_ceiling;
	#ifndef SOLAR_THREAD
	max_seconds = (INT_MAX - NFT_PCLOSE_SPIN_ATTEMPTS) /
		NFT_PCLOSE_ATTEMPTS_PER_SEC;
	if (seconds > max_seconds) seconds = max_seconds;

	return NFT_PCLOSE_SPIN_ATTEMPTS +
		(seconds * NFT_PCLOSE_ATTEMPTS_PER_SEC);
	#else
	return seconds;
	#endif
}

#ifdef SPINE_NFT_PCLOSE_TESTING
int nft_pclose_grace_attempts_for_test(void) {
	return nft_pclose_grace_attempts();
}
#endif

#ifdef SPINE_NFT_PCLOSE_TESTING
extern int spine_reap_child_bounded_test(pid_t, int *, int);
#define NFT_PCLOSE_REAP spine_reap_child_bounded_test
#else
#define NFT_PCLOSE_REAP spine_reap_child_bounded
#endif

/* Detach the entry for fd from PidList and hand the caller sole ownership.
   The close() happens under ListMutex on purpose: nft_popen() walks PidList to
   build the child's posix_spawn close list, so a descriptor closed outside the
   lock can be handed to posix_spawn_file_actions_addclose() after the number
   has been reused. Unlinking in the same critical section is what makes a
   second closer see EBADF instead of racing this one to free().

   Keep this noinline: GCC 12.2 emits -Wclobbered for the local when it is
   inlined into nft_pclose()'s pthread cleanup macro scope. */
static __attribute__((noinline)) struct pid *
pid_list_close_and_take(int fd)
{
	struct pid **link;
	struct pid *cur = NULL;

	pthread_mutex_lock(&ListMutex);

	for (link = &PidList; *link != NULL; link = &(*link)->next) {
		if ((*link)->fd == fd) {
			cur = *link;
			(void)close(cur->fd);
			cur->fd = -1;
			*link = cur->next;
			cur->next = NULL;
			break;
		}
	}

	pthread_mutex_unlock(&ListMutex);

	return cur;
}

int spine_set_cloexec(int fd) {
	int flags;

	flags = fcntl(fd, F_GETFD);
	if (flags < 0) {
		SPINE_LOG(("ERROR: Unable to read descriptor flags on fd %d: %s", fd, strerror(errno)));
		return -1;
	}

	if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != 0) {
		SPINE_LOG(("ERROR: Unable to set close-on-exec on fd %d: %s", fd, strerror(errno)));
		return -1;
	}

	return 0;
}

/*! \fn static int open_pipe_cloexec(int pdes[2])
 *  \brief open a pipe whose descriptors are not inherited across exec
 *
 *  nft_popen() creates the pipe before taking ListMutex, so a second thread
 *  can spawn while these descriptors are live. Without close-on-exec that
 *  child holds the first thread's write end, the first thread never sees EOF,
 *  and it blocks to script_timeout for a data source that answered.
 *
 *  pipe2(pdes, O_CLOEXEC) would set the flag atomically, but it needs
 *  _GNU_SOURCE on glibc and spine defines no feature macro, so the fcntl()
 *  pair stays. It leaves a window between the two calls, which is narrower
 *  than none.
 *
 *  \return TRUE on success, FALSE with the descriptors closed on failure
 */
int spine_open_pipe_cloexec(int pdes[2]) {
	if (pipe(pdes) < 0) {
		SPINE_LOG(("ERROR: Unable to create a pipe: %s", strerror(errno)));
		return FALSE;
	}

	/* spine_set_cloexec() has already said which descriptor failed and why;
	 * a descriptor that stays inheritable is worse than no pipe at all, so
	 * this fails rather than continuing without the flag. */
	if (spine_set_cloexec(pdes[0]) != 0 || spine_set_cloexec(pdes[1]) != 0) {
		(void)close(pdes[0]);
		(void)close(pdes[1]);

		/* the caller owns nothing on failure, so do not leave it holding two
		   descriptor numbers that now belong to whoever opens next; a caller
		   with one cleanup path would close them a second time */
		pdes[0] = -1;
		pdes[1] = -1;

		return FALSE;
	}

	return TRUE;
}

int spine_spawnattr_sigpipe_default(posix_spawnattr_t *attr) {
	sigset_t defaults;
	int rc;

	if (attr == NULL) {
		errno = EINVAL;
		return -1;
	}

	rc = posix_spawnattr_init(attr);
	if (rc != 0) {
		errno = rc;
		return -1;
	}

	sigemptyset(&defaults);
	sigaddset(&defaults, SIGPIPE);
	rc = posix_spawnattr_setsigdefault(attr, &defaults);
	if (rc == 0) rc = posix_spawnattr_setflags(attr, POSIX_SPAWN_SETSIGDEF);
	if (rc != 0) {
		posix_spawnattr_destroy(attr);
		errno = rc;
		return -1;
	}

	return 0;
}

/*! \fn static int reap_child_bounded(pid_t pid, int *pstat, int attempts)
 *  \return 0 when reaped, 1 when still running after attempts, -1 on error
 */
int spine_reap_child_bounded(pid_t pid, int *pstat, int attempts) {
	int attempt;
	pid_t waited;

	if (pstat == NULL) {
		return -1;
	}

	for (attempt = 0; attempt < attempts; attempt++) {
		do {
			waited = waitpid(pid, pstat, WNOHANG);
		} while (waited < 0 && errno == EINTR);

		if (waited == pid) {
			return 0;
		}

		if (waited < 0 && errno == ECHILD) {
			/* someone else reaped it, so no status is available */
			*pstat = 0;
			return 0;
		}

		if (waited < 0) {
			/* leave errno as waitpid set it; nft_pclose() reports it */
			return -1;
		}

		/* The delay is load-bearing: without it the attempts are spent in
		   nanoseconds and SIGKILL lands before the child can exit.
		 
		   Starting at the full 50ms charged that to every script that exits a
		   moment after closing stdout, which is the common case for anything
		   that flushes or tears down an interpreter. nft_pclose() runs while
		   the caller still holds an available_scripts token, so that delay
		   costs poller capacity rather than one thread. Spin briefly first,
		   then settle. The attempt count and so the time to SIGKILL are
		   unchanged. */
		#ifndef SOLAR_THREAD
		if (attempt < NFT_PCLOSE_SPIN_ATTEMPTS) {
			usleep(NFT_PCLOSE_SPIN_USEC);
		} else {
			usleep(NFT_PCLOSE_REAP_USEC);
		}
		#else
		sleep(1);
		#endif
	}

	return 1;
}

/*! ------------------------------------------------------------------------------
 *
 *  nft_popen
 *
 *  The nft_popen() function forks a command in a child process, and returns
 *  a pipe that is connected to the child's standard input and output. It is
 *  like the standard popen() call, except that it does not dfopen() the pipe
 *  file descriptor in order to return a stdio FILE *. This is useful if you
 *  wish to use select()- or poll()-driven IO.
 *
 *  The mode argument is defined as in standard popen().
 *
 *  On success, returns a file descriptor, or -1 on error.
 *  On failure, returns -1, with errno set to one of:
 *	EINVAL  The mode argument is incorrect.
 *	EMFILE	pipe() failed.
 *	ENFILE  pipe() failed.
 *	ENOMEM  malloc() failed.
 *	EAGAIN  fork() failed.
 *
 *------------------------------------------------------------------------------
 */
/* WARNING: command is passed to /bin/sh -c without shell escaping.
 * The caller MUST ensure command originates from a trusted source
 * (the Cacti database). Do not pass user-controlled input directly. */
int nft_popen(const char * command, const char * type) {
	struct pid *cur;
	struct pid *p;
	int    pdes[2];
	int     inherit_fd = -1;
	int    fd, twoway;
	pid_t  pid;
	char   *argv[4];
	char   *command_copy;
	char   shell_cmd[] = "sh";
	char   shell_flag[] = "-c";
	int    cancel_state;
	extern char **environ;
	int    retry_count = 0;

	/* On platforms where pipe() is bidirectional,
	 * "r+" gives two-way communication.
	 */
	if (strchr(type, '+')) {
		twoway = 1;
		type = "r+";
	}else {
		twoway = 0;
		if ((*type != 'r' && *type != 'w') || type[1]) {
			errno = EINVAL;
			return -1;
		}
	}

	if (!spine_open_pipe_cloexec(pdes))
		return -1;

	/* Disable thread cancellation from this point forward. */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);

	if ((cur = malloc(sizeof(struct pid))) == NULL) {
		(void)close(pdes[0]);
		(void)close(pdes[1]);
		pthread_setcancelstate(cancel_state, NULL);
		return -1;
	}

	if ((command_copy = strdup(command)) == NULL) {
		(void)close(pdes[0]);
		(void)close(pdes[1]);
		free(cur);
		pthread_setcancelstate(cancel_state, NULL);
		return -1;
	}

	argv[0] = shell_cmd;
	argv[1] = shell_flag;
	argv[2] = command_copy;
	argv[3] = NULL;

	/* Lock the list mutex prior to forking, to ensure that
	 * the child process sees PidList in a consistent list state.
	 */
	pthread_mutex_lock(&ListMutex);

	/* Drain anything a previous nft_pclose() gave up on. Doing it here means the
	   list empties on the next script poll rather than waiting for another
	   failure to trigger a sweep. */
	nft_sweep_abandoned();

	/* Build file actions for posix_spawn to replace vfork+execve. */
	posix_spawn_file_actions_t fa;
	posix_spawnattr_t attr;
	int fa_error;
	int attr_valid = FALSE;
	fa_error = posix_spawn_file_actions_init(&fa);
	if (fa_error != 0) {
		SPINE_LOG(("ERROR: SCRIPT: posix_spawn_file_actions_init failed"));
		(void)close(pdes[0]);
		(void)close(pdes[1]);
		pthread_mutex_unlock(&ListMutex);
		free(command_copy);
		free(cur);
		pthread_setcancelstate(cancel_state, NULL);
		errno = fa_error;
		return -1;
	}
	if (spine_spawnattr_sigpipe_default(&attr) != 0) {
		SPINE_LOG(("ERROR: SCRIPT: posix_spawnattr setup failed: %s", strerror(errno)));
		goto spawn_failed;
	}
	attr_valid = TRUE;

	/* File actions execute in order. Close every parent-side pipe belonging to
	 * an older popen before installing this child's stdin/stdout. An older pipe
	 * can occupy fd 0 or 1 when Spine starts with standard descriptors closed;
	 * closing it after dup2 would instead close the new redirect, while skipping
	 * it silently cross-wires two scripts. The new pdes[] and inherit_fd are all
	 * simultaneously open in the parent, so none can share an older p->fd. */
	for (p = PidList; p; p = p->next) {
		posix_spawn_file_actions_addclose(&fa, p->fd);
	}

	/* The pipe ends are close-on-exec, which is the point: another thread
	 * spawning in this window must not inherit them. The child needs its own
	 * end, and dup2 clears the flag on its target, so the usual paths are
	 * fine.
	 *
	 * When the end already sits on the descriptor it is destined for, there is
	 * no dup2 to clear anything and the child would exec with that descriptor
	 * closed. That happens whenever stdin or stdout was closed before this
	 * call, which for a daemon is not exotic, and the failure is silent: every
	 * script data source records U. dup() the end to a fresh descriptor, mark
	 * that temporary copy close-on-exec against concurrent spawns, and let this
	 * child's file action dup2 from it (clearing the flag on the target). */
	if (*type == 'r') {
		posix_spawn_file_actions_addclose(&fa, pdes[0]);
		if (pdes[1] != STDOUT_FILENO) {
			posix_spawn_file_actions_adddup2(&fa, pdes[1], STDOUT_FILENO);
			posix_spawn_file_actions_addclose(&fa, pdes[1]);
			if (twoway)
				posix_spawn_file_actions_adddup2(&fa, STDOUT_FILENO, STDIN_FILENO);
		} else {
			inherit_fd = dup(pdes[1]);

			if (inherit_fd < 0 || spine_set_cloexec(inherit_fd) != 0) {
				SPINE_LOG(("ERROR: Unable to duplicate the pipe for the child: %s", strerror(errno)));
				goto spawn_failed;
			}

			posix_spawn_file_actions_adddup2(&fa, inherit_fd, STDOUT_FILENO);
			posix_spawn_file_actions_addclose(&fa, inherit_fd);

			if (twoway)
				posix_spawn_file_actions_adddup2(&fa, STDOUT_FILENO, STDIN_FILENO);
		}
	} else {
		if (pdes[0] != STDIN_FILENO) {
			posix_spawn_file_actions_adddup2(&fa, pdes[0], STDIN_FILENO);
			posix_spawn_file_actions_addclose(&fa, pdes[0]);
		} else {
			inherit_fd = dup(pdes[0]);

			if (inherit_fd < 0 || spine_set_cloexec(inherit_fd) != 0) {
				SPINE_LOG(("ERROR: Unable to duplicate the pipe for the child: %s", strerror(errno)));
				goto spawn_failed;
			}

			posix_spawn_file_actions_adddup2(&fa, inherit_fd, STDIN_FILENO);
			posix_spawn_file_actions_addclose(&fa, inherit_fd);
		}
		posix_spawn_file_actions_addclose(&fa, pdes[1]);
	}

	/* Spawn the child process with retry on EAGAIN/ENOMEM. */
	#if defined(__CYGWIN__)
	const char *spawn_shell = (set.cygwinshloc == 0) ? "sh.exe" : "/bin/sh";
	#else
	const char *spawn_shell = "/bin/sh";
	#endif

	int spawn_err;
	retry:
	spawn_err = posix_spawn(&pid, spawn_shell, &fa, &attr, argv, environ);

	if (spawn_err != 0) {
		if ((spawn_err == EAGAIN || spawn_err == ENOMEM) && retry_count < 3) {
			retry_count++;
			usleep(50000);
			goto retry;
		}

		SPINE_LOG(("ERROR: SCRIPT: posix_spawn failed: %s", strerror(spawn_err)));

spawn_failed:
		/* One teardown for every failure after the file actions exist and the
		 * list mutex is held. ListMutex is process-global, so a path that
		 * returns still holding it wedges every later nft_popen() and
		 * nft_pclose() in every poller thread and the daemon stops collecting
		 * script data until it is restarted. */
		posix_spawn_file_actions_destroy(&fa);
		if (attr_valid) posix_spawnattr_destroy(&attr);

		if (inherit_fd != -1) {
			(void)close(inherit_fd);
			inherit_fd = -1;
		}

		(void)close(pdes[0]);
		(void)close(pdes[1]);
		pthread_mutex_unlock(&ListMutex);
		free(command_copy);
		free(cur);
		pthread_setcancelstate(cancel_state, NULL);
		return -1;
	}
	posix_spawnattr_destroy(&attr);
	attr_valid = FALSE;

	posix_spawn_file_actions_destroy(&fa);

	/* The child holds its own duplicate. Keeping this one would hold the pipe's
	 * write end open, so the reader never sees EOF and exec_poll() blocks to
	 * script_timeout on a script that already answered. That is the failure the
	 * close-on-exec work exists to prevent. */
	if (inherit_fd != -1) {
		(void)close(inherit_fd);
		inherit_fd = -1;
	}

	/* Parent. */
	if (*type == 'r') {
		fd = pdes[0];
		(void)close(pdes[1]);
	}else {
		fd = pdes[1];
		(void)close(pdes[0]);
	}

	/* Link into list of file descriptors. */
	cur->fd   = fd;
	cur->pid  = pid;
	cur->next = PidList;
	PidList   = cur;

	/* Unlock the mutex, and restore caller's cancellation state. */
	pthread_mutex_unlock(&ListMutex);
	free(command_copy);
	pthread_setcancelstate(cancel_state, NULL);

	return fd;
}

/*! ------------------------------------------------------------------------------
 *
 *  nft_pchild
 *
 *  Get the pid of the child process for an fd created by ntf_popen().
 *
 *  On success, the pid of the child process is returned.
 *  On failure, nft_pchild() returns -1, with errno set to:
 *
 *    EBADF	The fd is not an active nft_popen() file descriptor.
 *
 *------------------------------------------------------------------------------
 */
int nft_pchild(int fd) {
	struct pid *cur;
	pid_t	pid = 0;

	/* Find the appropriate file descriptor. */
	pthread_mutex_lock(&ListMutex);
	for (cur = PidList; cur; cur = cur->next)
		if (cur->fd == fd) {
			pid = cur->pid;
			break;
	}

	pthread_mutex_unlock(&ListMutex);

	if (cur == NULL) {
		errno = EBADF;
		return -1;
	}

	return pid;
}

/*! ------------------------------------------------------------------------------
 *
 *  nft_pclose
 *
 *  Close the pipe and wait for the status of the child process.
 *
 *  On success, the exit status of the child process is returned.
 *  On failure, nft_pclose() returns -1, with errno set to:
 *
 *    EBADF	The fd is not an active popen() file descriptor.
 *    ETIMEDOUT	The child outlived the TERM/KILL budgets.
 *    otherwise	The errno reported by waitpid().
 *
 *  This call is cancellable.
 *
 *------------------------------------------------------------------------------
 */
int
nft_pclose(int fd)
{
	struct pid *cur;
	int		pstat;
	int		reap_result;
	int		reap_errno = ECHILD;
	int		cancel_state;
	int		abandon_cancel_state = PTHREAD_CANCEL_ENABLE;
	int		abandon_cancel_held = FALSE;
	pid_t	pid;

	/* Detaching transfers exclusive ownership of the entry to this thread, so
	 * a concurrent closer gets EBADF rather than racing us to close(), wait()
	 * and free() the same child. Cancellation stays disabled until the cleanup
	 * handler is responsible for the detached entry; a cancel in that gap would
	 * leak it, since nothing else can reach it any more.
	 */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);

	cur = pid_list_close_and_take(fd);

	if (cur == NULL) {
		pthread_setcancelstate(cancel_state, NULL);
		errno = EBADF;
		return -1;
	}

	pthread_cleanup_push(close_cleanup, cur);

	pthread_setcancelstate(cancel_state, NULL);

	/* Give the child the configured time to exit after its pipe closes. A
	 * still-live child gets SIGTERM and another bounded grace period before
	 * SIGKILL; ordinary successful scripts are never killed outright. */
	reap_result = NFT_PCLOSE_REAP(cur->pid, &pstat, nft_pclose_grace_attempts());
	if (reap_result < 0 && errno != 0) reap_errno = errno;
	switch (reap_result) {
	case 0:
		pid = cur->pid;
		break;
	case 1:
		(void)kill(cur->pid, SIGTERM);
		reap_result = NFT_PCLOSE_REAP(cur->pid, &pstat, NFT_PCLOSE_SIGNAL_ATTEMPTS);
		if (reap_result < 0 && errno != 0) reap_errno = errno;
		if (reap_result == 0) {
			pid = cur->pid;
		} else if (reap_result == 1) {
			(void)kill(cur->pid, SIGKILL);
			reap_result = NFT_PCLOSE_REAP(cur->pid, &pstat, NFT_PCLOSE_SIGNAL_ATTEMPTS);
			if (reap_result < 0 && errno != 0) reap_errno = errno;
			if (reap_result == 0) {
				pid = cur->pid;
			} else {
				nft_pclose_abandon(cur->pid,
					reap_result == 1 ? "kill budget expired" : "waitpid failed after SIGKILL",
					&abandon_cancel_held, &abandon_cancel_state);
				errno = reap_result == 1 ? ETIMEDOUT : reap_errno;
				pid = -1;
			}
		} else {
			nft_pclose_abandon(cur->pid, "waitpid failed after SIGTERM",
				&abandon_cancel_held, &abandon_cancel_state);
			errno = reap_errno;
			pid = -1;
		}
		break;
	default:
		nft_pclose_abandon(cur->pid, "waitpid failed",
			&abandon_cancel_held, &abandon_cancel_state);
		errno = reap_errno;
		pid = -1;
		break;
	}

	if (pid == -1) reap_errno = errno;
	pthread_cleanup_pop(0);	/* Normal path: this thread still owns cur. */

	SPINE_FREE(cur);
	if (pid == -1) errno = reap_errno;
	if (abandon_cancel_held) {
		pthread_setcancelstate(abandon_cancel_state, NULL);
	}
	return (pid == -1 ? -1 : pstat);
}

/*! ------------------------------------------------------------------------------
  * nft_sweep_abandoned	- reap any child a previous nft_pclose() gave up on.
  *
  * Called with ListMutex held. WNOHANG only: this runs on a poller thread and
  * must never block on a child that is still stuck.
  *------------------------------------------------------------------------------
 */
static void
nft_sweep_abandoned(void)
{
	int	i = 0;
	int	status;
	pid_t	waited;

	while (i < AbandonedCount) {
		do {
			waited = waitpid(AbandonedPids[i], &status, WNOHANG);
		} while (waited < 0 && errno == EINTR);

		if (waited == AbandonedPids[i] || (waited < 0 && errno == ECHILD)) {
			SPINE_LOG_DEBUG(("DEBUG: Reaped abandoned script child pid %ld", (long) AbandonedPids[i]));
			AbandonedPids[i] = AbandonedPids[AbandonedCount - 1];
			AbandonedCount--;
		} else {
			i++;
		}
	}
}

/*! ------------------------------------------------------------------------------
  * nft_abandoned_pending	- sweep, then report how many pids are still parked.
  *
  * Takes ListMutex itself, so a caller that already holds it uses
  * nft_sweep_abandoned() directly.
  *------------------------------------------------------------------------------
 */
int
nft_abandoned_pending(void)
{
	int	remaining;
	int	oldstate;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);
	pthread_mutex_lock(&ListMutex);

	nft_sweep_abandoned();
	remaining = AbandonedCount;

	pthread_mutex_unlock(&ListMutex);
	pthread_setcancelstate(oldstate, NULL);

	return remaining;
}

#ifdef SPINE_NFT_PCLOSE_TESTING
void nft_fill_abandoned_for_test(pid_t pid) {
	int i;
	pthread_mutex_lock(&ListMutex);
	for (i = 0; i < NFT_ABANDONED_MAX; i++) AbandonedPids[i] = pid;
	AbandonedCount = NFT_ABANDONED_MAX;
	pthread_mutex_unlock(&ListMutex);
}
#endif

/*! ------------------------------------------------------------------------------
  * nft_abandon_child	- record a child that outlived its kill budget.
  *
  * The pid and the reason are logged either way. A silent drop leaves PID
  * exhaustion with nothing in the log pointing at its cause.
  *------------------------------------------------------------------------------
 */
void
nft_abandon_child(pid_t pid, const char *reason)
{
	int	parked;
	int	oldstate;

	/* nft_pclose() calls this inside its pthread_cleanup_push() region. A cancel
	   delivered while this held ListMutex would run close_cleanup() with the
	   lock still held, so take it uncancellable. */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);

	pthread_mutex_lock(&ListMutex);

	nft_sweep_abandoned();

	parked = (AbandonedCount < NFT_ABANDONED_MAX);

	if (parked) {
		AbandonedPids[AbandonedCount++] = pid;
	}

	pthread_mutex_unlock(&ListMutex);

	#ifdef SPINE_NFT_PCLOSE_TESTING
	nft_abandon_parked_test_hook();
	#endif

	pthread_setcancelstate(oldstate, NULL);

	if (parked) {
		SPINE_LOG(("WARNING: SCRIPT: pid %ld survived SIGKILL (%s); parked for reaping", (long) pid, reason));
	} else {
		SPINE_LOG(("ERROR: SCRIPT: pid %ld survived SIGKILL (%s) and the abandoned list is full; it will remain a zombie", (long) pid, reason));
	}
}

/*! ------------------------------------------------------------------------------
  * close_cleanup	- close the pipe and free the pidlist entry.
  *------------------------------------------------------------------------------
 */
static void
close_cleanup(void * arg)
{
	struct pid * cur = arg;
	int status;
	int reap_result;
	pid_t pid;

	/* Runs only when a cancel arrives after nft_pclose() detached the entry, so
	 * cur is already off PidList, its descriptor is already closed, and this
	 * thread is its only owner. Nothing needs the list here.
	 *
	 * The child still has to be reaped. Spine has no SIGCHLD handler and no
	 * waitpid(-1), so returning without reaping would leave a zombie for the
	 * daemon's lifetime. Check before killing so an already-exited and reused
	 * pid can never be signalled.
	 */
	do {
		pid = waitpid(cur->pid, NULL, WNOHANG);
	} while (pid < 0 && errno == EINTR);

	if (pid == 0) {
		(void)kill(cur->pid, SIGKILL);
		reap_result = spine_reap_child_bounded(cur->pid, &status,
			NFT_PCLOSE_SIGNAL_ATTEMPTS);
		if (reap_result != 0) {
			nft_abandon_child(cur->pid,
				reap_result == 1 ? "cancel cleanup kill budget expired" :
				"cancel cleanup waitpid failed after SIGKILL");
		}
	}

	SPINE_FREE(cur);
}
