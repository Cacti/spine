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

static void	close_cleanup(void *);

/* nft_pclose() must not block a poller thread indefinitely. A script that
   writes its value and then lingers, or that ignores SIGPIPE, would otherwise
   pin the thread across polling cycles while holding its available_scripts
   token. Poll with WNOHANG, then escalate to SIGKILL. */
/* Budget to SIGKILL is about five seconds on both platforms. The counts differ
 * because the granularity does: everywhere else in the tree usleep() is simply
 * skipped under SOLAR_THREAD rather than replaced, so the coarsest wait
 * available there is a whole second and the attempt count scales to match.
 * Leaving the counts equal made the Solaris path roughly a hundred seconds,
 * longer than a polling cycle, while nft_pclose() holds an available_scripts
 * token throughout. */
#define NFT_PCLOSE_REAP_USEC 50000
#define NFT_PCLOSE_SPIN_USEC 200
#define NFT_PCLOSE_SPIN_ATTEMPTS 10
#ifndef SOLAR_THREAD
#define NFT_PCLOSE_TERM_ATTEMPTS 100
#define NFT_PCLOSE_KILL_ATTEMPTS 20
#else
#define NFT_PCLOSE_TERM_ATTEMPTS 5
#define NFT_PCLOSE_KILL_ATTEMPTS 2
#endif

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
		return FALSE;
	}

	return TRUE;
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

	/* Build file actions for posix_spawn to replace vfork+execve. */
	posix_spawn_file_actions_t fa;
	if (posix_spawn_file_actions_init(&fa) != 0) {
		SPINE_LOG(("ERROR: SCRIPT: posix_spawn_file_actions_init failed"));
		(void)close(pdes[0]);
		(void)close(pdes[1]);
		pthread_mutex_unlock(&ListMutex);
		free(command_copy);
		free(cur);
		pthread_setcancelstate(cancel_state, NULL);
		return -1;
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
	 * script data source records U. dup() the end to a fresh descriptor, which
	 * does not carry the flag, and let the child dup2 from that. */
	if (*type == 'r') {
		posix_spawn_file_actions_addclose(&fa, pdes[0]);
		if (pdes[1] != STDOUT_FILENO) {
			posix_spawn_file_actions_adddup2(&fa, pdes[1], STDOUT_FILENO);
			posix_spawn_file_actions_addclose(&fa, pdes[1]);
			if (twoway)
				posix_spawn_file_actions_adddup2(&fa, STDOUT_FILENO, STDIN_FILENO);
		} else {
			inherit_fd = dup(pdes[1]);

			if (inherit_fd < 0) {
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

			if (inherit_fd < 0) {
				SPINE_LOG(("ERROR: Unable to duplicate the pipe for the child: %s", strerror(errno)));
				goto spawn_failed;
			}

			posix_spawn_file_actions_adddup2(&fa, inherit_fd, STDIN_FILENO);
			posix_spawn_file_actions_addclose(&fa, inherit_fd);
		}
		posix_spawn_file_actions_addclose(&fa, pdes[1]);
	}

	/* Close all other pipes in the child (Posix.2 requirement). */
	for (p = PidList; p; p = p->next)
		posix_spawn_file_actions_addclose(&fa, p->fd);

	/* Spawn the child process with retry on EAGAIN/ENOMEM. */
	#if defined(__CYGWIN__)
	const char *spawn_shell = (set.cygwinshloc == 0) ? "sh.exe" : "/bin/sh";
	#else
	const char *spawn_shell = "/bin/sh";
	#endif

	int spawn_err;
	retry:
	spawn_err = posix_spawn(&pid, spawn_shell, &fa, NULL, argv, environ);

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
 *    ECHILD	The waitpid() call failed.
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

	/* Find the appropriate file descriptor. */
	pthread_mutex_lock(&ListMutex);

	for (cur = PidList; cur; cur = cur->next)
	if (cur->fd == fd) break;

	pthread_mutex_unlock(&ListMutex);

	if (cur == NULL) {
		errno = EBADF;
		return -1;
	}

	/* The close and waitpid calls below are cancellation points.
	 * We want to ensure that the fd is closed and the PidList
	 * entry freed despite cancellation, so push a cleanup handler.
	 */
	pthread_cleanup_push(close_cleanup, cur);

	/* end the process nicely and then forcefully */
	(void)close(fd);

	cur->fd = -1;		/* Prevent the fd being closed twice. */

	switch (spine_reap_child_bounded(cur->pid, &pstat, NFT_PCLOSE_TERM_ATTEMPTS)) {
	case 0:
		pid = cur->pid;
		break;
	case 1:
		(void)kill(cur->pid, SIGKILL);
		if (spine_reap_child_bounded(cur->pid, &pstat, NFT_PCLOSE_KILL_ATTEMPTS) == 0) {
			pid = cur->pid;
		} else {
			errno = ETIMEDOUT;
			pid = -1;
		}
		break;
	default:
		pid = -1;
		break;
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
