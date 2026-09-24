/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2024 The Cacti Group                                 |
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

#define _GNU_SOURCE
#include "common.h"
#include "spine.h"
#include <fcntl.h>

static int nft_pipe_cloexec(int pipe_fds[2]) {
	#ifdef HAVE_PIPE2
	return pipe2(pipe_fds, O_CLOEXEC);
	#else
	int flags;

	thread_mutex_lock(LOCK_FORK);
	if (pipe(pipe_fds) < 0) {
		thread_mutex_unlock(LOCK_FORK);
		return -1;
	}
	flags = fcntl(pipe_fds[0], F_GETFD);
	if (flags < 0 || fcntl(pipe_fds[0], F_SETFD, flags | FD_CLOEXEC) < 0) {
		goto failure;
	}
	flags = fcntl(pipe_fds[1], F_GETFD);
	if (flags < 0 || fcntl(pipe_fds[1], F_SETFD, flags | FD_CLOEXEC) < 0) {
		goto failure;
	}
	thread_mutex_unlock(LOCK_FORK);
	return 0;

	failure:
	flags = errno;
	close(pipe_fds[0]);
	close(pipe_fds[1]);
	thread_mutex_unlock(LOCK_FORK);
	errno = flags;
	return -1;
	#endif
}

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
   per cycle against RLIMIT_NPROC. The pids are parked here and swept with
   WNOHANG instead, opportunistically at the top of nft_popen(). Bounded: past
   the cap the pid is logged and dropped, because an unbounded list trades a
   pid leak for a memory leak. */
#define NFT_ABANDONED_MAX 64
static pid_t	AbandonedPids[NFT_ABANDONED_MAX];
static int	AbandonedCount;

static void	close_cleanup(void *);

/*! ------------------------------------------------------------------------------
  * nft_sweep_abandoned	- reap any child a previous nft_pclose() gave up on.
  *
  * Called with ListMutex held. WNOHANG only: this runs on a poller thread and
  * must never block on a child that is still stuck.
  *------------------------------------------------------------------------------
 */
static void nft_sweep_abandoned(void) {
	int	i = 0;
	int	status;
	pid_t	waited;
	int	eintr_budget;

	while (i < AbandonedCount) {
		/* Bounded so a stream of caught signals cannot spin this loop
		 * forever while ListMutex is held; an exhausted budget just leaves
		 * the pid for the next sweep. */
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
  * nft_abandon_child	- record a child that outlived its kill budget.
  *
  * The pid and the reason are logged either way. A silent drop leaves PID
  * exhaustion with nothing in the log pointing at its cause.
  *------------------------------------------------------------------------------
 */
static void nft_abandon_child(pid_t pid, const char *reason) {
	int	parked;

	pthread_mutex_lock(&ListMutex);

	nft_sweep_abandoned();

	parked = (AbandonedCount < NFT_ABANDONED_MAX);

	if (parked) {
		AbandonedPids[AbandonedCount++] = pid;
	}

	pthread_mutex_unlock(&ListMutex);

	if (parked) {
		SPINE_LOG(("WARNING: SCRIPT: pid %ld survived SIGKILL (%s); parked for reaping", (long) pid, reason));
	} else {
		SPINE_LOG(("ERROR: SCRIPT: pid %ld survived SIGKILL (%s) and the abandoned list is full; it will remain a zombie", (long) pid, reason));
	}
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
int nft_popen(const char * command, const char * type) {
	struct pid *cur;
	struct pid *p;
	int    pdes[2];
	int    fd, pid, twoway;
	char   *argv[4];
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

	if (nft_pipe_cloexec(pdes) < 0)
		return -1;

	/* Disable thread cancellation from this point forward. */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);

	if ((cur = malloc(sizeof(struct pid))) == NULL) {
		(void)close(pdes[0]);
		(void)close(pdes[1]);
		pthread_setcancelstate(cancel_state, NULL);
		return -1;
	}

	argv[0] = "sh";
	argv[1] = "-c";
	argv[2] = (char *)command;
	argv[3] = NULL;

	/* Lock the list mutex prior to forking, to ensure that
	 * the child process sees PidList in a consistent list state.
	 */
	pthread_mutex_lock(&ListMutex);

	/* Drain anything a previous nft_pclose() gave up on. Doing it here means
	   the list empties on the next script poll rather than waiting for
	   another failure to trigger a sweep. */
	nft_sweep_abandoned();

	/* Fork. */
	retry:
	thread_mutex_lock(LOCK_FORK);
	pid = vfork();
	if (pid != 0) {
		thread_mutex_unlock(LOCK_FORK);
	}
	switch (pid) {
	case -1:		/* Error. */
		switch (errno) {
		case EAGAIN:
			if (retry_count < 3) {
				retry_count++;
				#ifndef SOLAR_THREAD
				/* take a moment */
				usleep(50000);
				#endif
				goto retry;
			}else{
				SPINE_LOG(("ERROR: SCRIPT: Cound not fork. Out of Resources nft_popen.c"));
			}
			break;
		case ENOMEM:
			if (retry_count < 3) {
				retry_count++;
				#ifndef SOLAR_THREAD
				/* take a moment */
				usleep(50000);
				#endif
				goto retry;
			}else{
				SPINE_LOG(("ERROR: SCRIPT Cound not fork. Out of Memory nft_popen.c"));
			}
			break;
		default:
			SPINE_LOG(("ERROR: SCRIPT Cound not fork. Unknown Reason nft_popen.c"));
		}

		(void)close(pdes[0]);
		(void)close(pdes[1]);
		pthread_mutex_unlock(&ListMutex);
		pthread_setcancelstate(cancel_state, NULL);

		return -1;
		/* NOTREACHED */
	case 0:			/* Child. */
		if (*type == 'r') {
			/* The dup2() to STDIN_FILENO is repeated to avoid
			 * writing to pdes[1], which might corrupt the
			 * parent's copy.  This isn't good enough in
			 * general, since the _exit() is no return, so
			 * the compiler is free to corrupt all the local
			 * variables.
			 */
			(void)close(pdes[0]);
			if (pdes[1] != STDOUT_FILENO) {
				(void)dup2(pdes[1], STDOUT_FILENO);
				(void)close(pdes[1]);
				if (twoway)
					(void)dup2(STDOUT_FILENO, STDIN_FILENO);
			}else if (twoway && (pdes[1] != STDIN_FILENO))
				(void)dup2(pdes[1], STDIN_FILENO);
		}else {
			if (pdes[0] != STDIN_FILENO) {
				(void)dup2(pdes[0], STDIN_FILENO);
				(void)close(pdes[0]);
			}
			(void)close(pdes[1]);
		}

		/* Close all the other pipes in the child process.
		 * Posix.2 requires this, tho I don't know why.
		 */
		for (p = PidList; p; p = p->next)
			(void)close(p->fd);
		(void)fcntl(STDIN_FILENO, F_SETFD, 0);
		(void)fcntl(STDOUT_FILENO, F_SETFD, 0);

		/* Execute the command. */
		#if defined(__CYGWIN__)
		if (set.cygwinshloc == 0) {
			execve("sh.exe", argv, environ);
		}else{
			execve("/bin/sh", argv, environ);
		}
		#else
		execve("/bin/sh", argv, environ);
		#endif
		_exit(127);
		/* NOTREACHED */
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
 *    ECHILD	The waitpid() call failed.
 *    ETIMEDOUT	The child had not exited by the end of the bounded check; it
 *    		has been killed and parked for the abandoned-pid sweep to reap.
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
	pid_t	pid;
	pid_t	waited;
	int		attempt;
	int		eintr_budget;
	int		reap_state;	/* 0 reaped, 1 still running, -1 waitpid() error */

	/* Find the appropriate file descriptor. */
	pthread_mutex_lock(&ListMutex);

	for (cur = PidList; cur; cur = cur->next)
	if (cur->fd == fd) break;

	pthread_mutex_unlock(&ListMutex);

	if (cur == NULL) {
		errno = EBADF;
		return -1;
	}

	/* The close call below is a cancellation point.
	 * We want to ensure that the fd is closed and the PidList
	 * entry freed despite cancellation, so push a cleanup handler.
	 */
	pthread_cleanup_push(close_cleanup, cur);

	/* end the process nicely and then forcefully */
	(void)close(fd);

	cur->fd = -1;		/* Prevent the fd being closed twice. */

	/* The script already had its one chance to write and its pipe is now
	 * closed. Give it a brief (~20ms), non-escalating allowance to catch the
	 * common case where it has already exited or is about to on seeing EOF -
	 * without it, ordinary fork/exec/exit scheduling latency would flag a
	 * script that is not actually misbehaving. Anything still running past
	 * that is killed and handed to the abandoned-pid sweep instead of this
	 * thread waiting for it; this used to block here indefinitely. */
	reap_state = 1;
	for (attempt = 0; attempt < 100; attempt++) {
		eintr_budget = 1000;
		do {
			waited = waitpid(cur->pid, &pstat, WNOHANG);
		} while (waited < 0 && errno == EINTR && --eintr_budget > 0);

		if (waited == cur->pid) {
			reap_state = 0;
			break;
		}

		if (waited < 0 && errno == ECHILD) {
			/* someone else reaped it, so no status is available */
			pstat = 0;
			reap_state = 0;
			break;
		}

		if (waited < 0) {
			reap_state = -1;
			break;
		}

		usleep(200);
	}

	if (reap_state == 0) {
		pid = cur->pid;
	} else if (reap_state == 1) {
		(void)kill(cur->pid, SIGKILL);
		nft_abandon_child(cur->pid, "did not exit before pipe close");
		errno = ETIMEDOUT;
		pid = -1;
	} else {
		/* waitpid() itself failed, so whether the child exited is unknown;
		 * kill it before parking so a still-running child is not left
		 * outside the sweep's reach. Preserve waitpid()'s errno. */
		int saved_errno = errno;
		(void)kill(cur->pid, SIGKILL);
		nft_abandon_child(cur->pid, "waitpid failed");
		errno = saved_errno;
		pid = -1;
	}

	pthread_cleanup_pop(1);	/* Execute the cleanup handler. */

	return (pid == -1 ? -1 : pstat);
}

/*! ------------------------------------------------------------------------------
  * close_cleanup	- close the pipe and free the pidlist entry.
  *------------------------------------------------------------------------------
 */
static void
close_cleanup(void * arg)
{
	struct pid * cur = arg;
	struct pid * prev;

	/* Close the pipe fd if necessary. */
	if (cur->fd >= 0) {
		(void)close(cur->fd);
	}

	/* Remove the entry from the linked list. */
	pthread_mutex_lock(&ListMutex);

	if (PidList == cur) {
		PidList =  cur->next;
	}else{
		for (prev = PidList; prev; prev = prev->next)
		if (prev->next == cur) {
			prev->next =  cur->next;
			break;
		}

		assert(prev != NULL);	/* Search should not fail */
	}

	pthread_mutex_unlock(&ListMutex);

	free(cur);
}
