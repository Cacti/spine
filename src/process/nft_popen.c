/*
 * SPDX-FileCopyrightText: 2004-2026 The Cacti Group
 * SPDX-FileCopyrightText: 2002 Xenadyne Inc.
 * SPDX-FileCopyrightText: 1988, 1993 The Regents of the University of California
 * SPDX-License-Identifier: GPL-2.0-or-later AND BSD-4-Clause AND LicenseRef-Xenadyne
 *
 * Fork maintenance: Thomas Vincent.
 * Project contributor history: CONTRIBUTORS.md.
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

#include "internal/common.h"
#include "app/spine.h"
#include "process/process_internal.h"
#include <spawn.h>
#include <fcntl.h>
#include <sys/wait.h>

/* An instance of this struct is created for each popen() fd. */
static struct pid {
	struct pid *next;
	int fd;
	pid_t pid;
} *PidList;

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
static pid_t AbandonedPids[NFT_ABANDONED_MAX];
static int AbandonedCount;

static void close_cleanup(void *);
static void nft_sweep_abandoned(void);

/* Close and remove an entry from the shared registry, then transfer exclusive
 * ownership to the caller.  Closing under ListMutex preserves the invariant
 * that every descriptor still visible to nft_popen() is open, so its
 * posix_spawn addclose walk cannot queue an already-closed descriptor.  Once
 * returned, no other thread can find or free the entry.
 * Keep this noinline: GCC 12.2 emits -Wclobbered for the helper local when it
 * is inlined into nft_pclose()'s pthread cleanup macro scope.
 */
static __attribute__((noinline)) struct pid *pid_list_close_and_take(int fd) {
	struct pid **link;
	struct pid *cur = NULL;

	pthread_mutex_lock(&ListMutex);

	for (link = &PidList; *link != NULL; link = &(*link)->next) {
		if ((*link)->fd == fd) {
			cur = *link;
			(void) close(cur->fd);
			cur->fd = -1;
			*link = cur->next;
			cur->next = NULL;
			break;
		}
	}

	pthread_mutex_unlock(&ListMutex);

	return cur;
}
/* nft_pclose() must not block a poller thread: a script that writes its
   value and then lingers, or that ignores signals, would otherwise pin the
   thread across polling cycles while holding its available_scripts token.
   It gets a brief (~20ms), non-escalating WNOHANG allowance via
   spine_reap_child_bounded() below - just enough to absorb ordinary
   fork/exec/exit scheduling latency (measured flaky under virtualized/loaded
   CI at the original 2ms budget), not to wait out a script that is actually
   still working. Anything still running past that is killed outright and
   handed to nft_abandon_child() so nft_sweep_abandoned() reaps it on a
   later, unrelated nft_popen() call instead of this thread waiting for it. */

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
int nft_popen(const char *command, const char *type) {
	struct pid *cur;
	struct pid *p;
	int pdes[2];
	int inherit_fd = -1;
	int fd, twoway;
	pid_t pid;
	char *argv[4];
	char *command_copy;
	char shell_cmd[] = "sh";
	char shell_flag[] = "-c";
	int cancel_state;
	extern char **environ;
	int retry_count = 0;
	/* nft_popen() reports why process creation failed through errno, as
	 * popen() does; cleanup below must not overwrite it. */
	int failure_errno = 0;
	posix_spawnattr_t attr;
	int attr_valid = FALSE;
	int attr_err;

	if (command == NULL || type == NULL) {
		errno = EINVAL;
		return -1;
	}

	/* On platforms where pipe() is bidirectional,
	 * "r+" gives two-way communication. Only the documented modes are
	 * accepted; any other "+" mode is a caller error, not a duplex request.
	 */
	if (strcmp(type, "r+") == 0) {
		twoway = 1;
	} else {
		twoway = 0;
		if ((*type != 'r' && *type != 'w') || type[1]) {
			errno = EINVAL;
			return -1;
		}
	}

	/* An ordinary pipe is one-way on Linux and macOS, so the duplex mode
	 * needs a socket pair to be readable and writable at the parent end. */
	if (twoway) {
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, pdes) < 0)
			return -1;

		if (spine_set_cloexec(pdes[0]) != 0 || spine_set_cloexec(pdes[1]) != 0) {
			(void) close(pdes[0]);
			(void) close(pdes[1]);
			return -1;
		}
	} else if (!spine_open_pipe_cloexec(pdes)) {
		return -1;
	}

	/* Disable thread cancellation from this point forward. */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);

	if ((cur = malloc(sizeof(*cur))) == NULL) {
		(void) close(pdes[0]);
		(void) close(pdes[1]);
		pthread_setcancelstate(cancel_state, NULL);
		return -1;
	}

	if ((command_copy = strdup(command)) == NULL) {
		(void) close(pdes[0]);
		(void) close(pdes[1]);
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
	if (posix_spawn_file_actions_init(&fa) != 0) {
		SPINE_LOG(("ERROR: SCRIPT: posix_spawn_file_actions_init failed"));
		(void) close(pdes[0]);
		(void) close(pdes[1]);
		pthread_mutex_unlock(&ListMutex);
		free(command_copy);
		free(cur);
		pthread_setcancelstate(cancel_state, NULL);
		return -1;
	}

	/* Each script leads its own process group so a timeout can kill the
	 * group. Killing only the shell left anything it had started running,
	 * still holding the pipe and counting against the process limit. */
	attr_err = posix_spawnattr_init(&attr);
	if (attr_err == 0) {
		attr_valid = TRUE;
		attr_err = posix_spawnattr_setpgroup(&attr, 0);
	}
	if (attr_err == 0) attr_err = posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP);
	if (attr_err != 0) {
		failure_errno = attr_err;
		SPINE_LOG(("ERROR: SCRIPT: posix_spawnattr setup failed: %s", strerror(attr_err)));
		goto spawn_failed;
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
	 * script data source records U. Duplicate the end to a fresh descriptor,
	 * explicitly mark that duplicate close-on-exec so concurrent children
	 * cannot inherit it, and let this child dup2 from it. dup2 clears the flag
	 * on its target. */
	if (*type == 'r') {
		posix_spawn_file_actions_addclose(&fa, pdes[0]);
		if (pdes[1] != STDOUT_FILENO) {
			posix_spawn_file_actions_adddup2(&fa, pdes[1], STDOUT_FILENO);
			posix_spawn_file_actions_addclose(&fa, pdes[1]);
			if (twoway)
				posix_spawn_file_actions_adddup2(&fa, STDOUT_FILENO, STDIN_FILENO);
		} else {
			inherit_fd = spine_dup_cloexec(pdes[1]);

			if (inherit_fd < 0) {
				failure_errno = errno;
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
			inherit_fd = spine_dup_cloexec(pdes[0]);

			if (inherit_fd < 0) {
				failure_errno = errno;
				SPINE_LOG(("ERROR: Unable to duplicate the pipe for the child: %s", strerror(errno)));
				goto spawn_failed;
			}

			posix_spawn_file_actions_adddup2(&fa, inherit_fd, STDIN_FILENO);
			posix_spawn_file_actions_addclose(&fa, inherit_fd);
		}
		posix_spawn_file_actions_addclose(&fa, pdes[1]);
	}

	/* Close all other pipes in the child (Posix.2 requirement). */
	for (p = PidList; p; p = p->next) {
		/* File actions run in order. Do not close a standard descriptor after
		 * this spawn has redirected a fresh pipe onto it merely because an
		 * older parent-side pipe happens to use the same descriptor number. */
		if ((*type == 'r' && p->fd == STDOUT_FILENO) ||
			(*type == 'r' && twoway && p->fd == STDIN_FILENO) ||
			(*type == 'w' && p->fd == STDIN_FILENO)) {
			continue;
		}
		posix_spawn_file_actions_addclose(&fa, p->fd);
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

		failure_errno = spawn_err;
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
			(void) close(inherit_fd);
			inherit_fd = -1;
		}

		(void) close(pdes[0]);
		(void) close(pdes[1]);
		pthread_mutex_unlock(&ListMutex);
		free(command_copy);
		free(cur);
		pthread_setcancelstate(cancel_state, NULL);
		if (failure_errno != 0) {
			errno = failure_errno;
		}
		return -1;
	}

	posix_spawn_file_actions_destroy(&fa);
	posix_spawnattr_destroy(&attr);

	/* The child holds its own duplicate. Keeping this one would hold the pipe's
	 * write end open, so the reader never sees EOF and exec_poll() blocks to
	 * script_timeout on a script that already answered. That is the failure the
	 * close-on-exec work exists to prevent. */
	if (inherit_fd != -1) {
		(void) close(inherit_fd);
		inherit_fd = -1;
	}

	/* Parent. */
	if (*type == 'r') {
		fd = pdes[0];
		(void) close(pdes[1]);
	} else {
		fd = pdes[1];
		(void) close(pdes[0]);
	}

	/* Link into list of file descriptors. */
	cur->fd = fd;
	cur->pid = pid;
	cur->next = PidList;
	PidList = cur;

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
	pid_t pid = 0;

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
 *  Close the pipe and check the child's status with a brief (~20ms),
 *  non-escalating bounded waitpid(). A child still running past that point,
 *  or one whose waitpid() call itself failed, is killed and handed to the
 *  abandoned-pid sweep rather than waited for here, so this call never
 *  blocks the caller on a lingering script.
 *
 *  On success, the exit status of the child process is returned.
 *  On failure, nft_pclose() returns -1, with errno set to:
 *
 *    EBADF	The fd is not an active popen() file descriptor.
 *    ETIMEDOUT	The child had not exited by the end of the bounded check; it
 *    		has been killed and parked for the abandoned-pid sweep to reap.
 *    (other)	The waitpid() call itself failed for a reason other than
 *    		ECHILD, which is treated as a successful reap; may be EINTR if
 *    		the bounded EINTR retry budget was exhausted.
 *
 *  This call is cancellable.
 *
 *------------------------------------------------------------------------------
 */
int nft_pclose(int fd) {
	struct pid *cur;
	int pstat;
	int cancel_state;
	pid_t pid;

	/* Cancellation must remain disabled until the detached entry is protected
	 * by the cleanup handler.  Detaching transfers exclusive ownership here.
	 */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
	cur = pid_list_close_and_take(fd);

	if (cur == NULL) {
		pthread_setcancelstate(cancel_state, NULL);
		errno = EBADF;
		return -1;
	}

	/* Install the cleanup handler before restoring cancellation. */
	pthread_cleanup_push(close_cleanup, cur);

	pthread_setcancelstate(cancel_state, NULL);

	/* The script already had its one chance to write and its pipe is now
	 * closed. Give it a brief (~20ms), non-escalating allowance to catch the
	 * common case where it has already exited or is about to on seeing EOF -
	 * without it, ordinary fork/exec/exit scheduling latency would flag a
	 * script that is not actually misbehaving. Anything still running past
	 * that is killed and handed to the abandoned-pid sweep instead of this
	 * thread waiting for it. */
	switch (spine_reap_child_bounded(cur->pid, &pstat, NFT_PCLOSE_SPIN_ATTEMPTS)) {
		case 0:
			pid = cur->pid;
			break;
		case 1:
			/* The negative pid reaches the script's whole process group. */
			(void) kill(-cur->pid, SIGKILL);
			nft_abandon_child(cur->pid, "did not exit before pipe close");
			errno = ETIMEDOUT;
			pid = -1;
			break;
		default:
			/* waitpid() itself failed, so whether the child exited is unknown;
		 * kill it before parking so a still-running child is not left
		 * outside the sweep's reach. Preserve waitpid()'s errno. */
			{
				int saved_errno = errno;
				(void) kill(-cur->pid, SIGKILL);
				nft_abandon_child(cur->pid, "waitpid failed");
				errno = saved_errno;
			}
			pid = -1;
			break;
	}

	pthread_cleanup_pop(1); /* Execute the cleanup handler. */

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
nft_sweep_abandoned(void) {
	int i = 0;
	int status;
	pid_t waited;
	int eintr_budget;

	while (i < AbandonedCount) {
		eintr_budget = 1000;
		do {
			waited = waitpid(AbandonedPids[i], &status, WNOHANG);
		} while (waited < 0 && errno == EINTR && --eintr_budget > 0);

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
int nft_abandoned_pending(void) {
	int remaining;
	int oldstate;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);
	pthread_mutex_lock(&ListMutex);

	nft_sweep_abandoned();
	remaining = AbandonedCount;

	pthread_mutex_unlock(&ListMutex);
	pthread_setcancelstate(oldstate, NULL);

	return remaining;
}

/*! ------------------------------------------------------------------------------
  * nft_abandon_child	- record a child that outlived its kill budget.
  *
  * The pid and the reason are logged either way. A silent drop leaves PID
  * exhaustion with nothing in the log pointing at its cause.
  *------------------------------------------------------------------------------
 */
void nft_abandon_child(pid_t pid, const char *reason) {
	int parked;
	int oldstate;

	/* nft_pclose() calls this inside its pthread_cleanup_push() region, and
	   close_cleanup() takes ListMutex. A cancel delivered while this held the
	   lock would run the handler straight into it, so hold it uncancellable. */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);

	pthread_mutex_lock(&ListMutex);

	nft_sweep_abandoned();

	parked = (AbandonedCount < NFT_ABANDONED_MAX);

	if (parked) {
		AbandonedPids[AbandonedCount++] = pid;
	}

	pthread_mutex_unlock(&ListMutex);

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
close_cleanup(void *arg) {
	struct pid *cur = arg;

	SPINE_FREE(cur);
}
