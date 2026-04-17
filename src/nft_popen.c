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
#include "platform/platform_error.h"
#include "platform/platform_process.h"
#include <signal.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>

extern char **environ;

/* Names a child must not inherit from spine's environment. Dynamic-linker
 * hijack vectors (the whole LD_ and DYLD_ namespace) and interpreter-
 * startup injection (BASH_ENV, ENV, PERL5OPT, PYTHONSTARTUP, PYTHONINSPECT,
 * RUBYOPT, NODE_OPTIONS) are the attack surface; everything else is the
 * operator's own config (custom PATH, PERL5LIB, PYTHONPATH for script
 * dependencies) and must pass through. IFS is forced to a safe value if
 * unset. The LD_ / DYLD_ check is a prefix match rather than an
 * enumerated list so a future linker variable (LD_DEBUG, LD_PROFILE,
 * DYLD_FALLBACK_LIBRARY_PATH, DYLD_VERSIONED_LIBRARY_PATH) is covered
 * without a code change. */
static const char *const spine_dangerous_env_exact[] = {
	"BASH_ENV=",
	"ENV=",
	"PERL5OPT=",
	"PYTHONSTARTUP=",
	"PYTHONINSPECT=",
	"RUBYOPT=",
	"NODE_OPTIONS=",
	NULL
};

static int spine_env_is_dangerous(const char *entry) {
	if (strncmp(entry, "LD_", 3) == 0)   return 1;
	if (strncmp(entry, "DYLD_", 5) == 0) return 1;
	for (size_t d = 0; spine_dangerous_env_exact[d]; d++) {
		size_t plen = strlen(spine_dangerous_env_exact[d]);
		if (strncmp(entry, spine_dangerous_env_exact[d], plen) == 0) return 1;
	}
	return 0;
}

/* Default PATH injected when the parent environment has none. The hardcoded
 * PATH is intentionally narrow so a missing PATH cannot cause a child to
 * resolve tools from a surprising directory. */
static const char spine_default_path[] =
	"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
static const char spine_default_ifs[]  = "IFS= \t\n";

/* Build a filtered copy of environ for a child. Returned array's strings are
 * borrowed from environ (do not free the entries), but the array itself is
 * heap-allocated and must be freed by the caller.
 *
 * Exposed (non-static) so the PHP Script Server spawn path in php.c can share
 * the same dynamic-linker hijack filter instead of passing raw environ. */
char **spine_build_child_env(void) {
	size_t n = 0;
	while (environ && environ[n]) n++;

	/* +3 for possible PATH, IFS, and NULL terminator. */
	char **new_env = calloc(n + 3, sizeof(char *));
	if (!new_env) return NULL;

	int has_path = 0;
	int has_ifs  = 0;
	size_t w = 0;
	for (size_t r = 0; r < n; r++) {
		if (spine_env_is_dangerous(environ[r])) continue;
		if (strncmp(environ[r], "PATH=", 5) == 0) has_path = 1;
		if (strncmp(environ[r], "IFS=",  4) == 0) has_ifs  = 1;
		new_env[w++] = environ[r];
	}
	if (!has_path) new_env[w++] = (char *)spine_default_path;
	if (!has_ifs)  new_env[w++] = (char *)spine_default_ifs;
	new_env[w] = NULL;
	return new_env;
}

/* An instance of this struct is created for each popen() fd. */
static struct pid
{
    struct pid *next;
    int		fd;
    spine_pid_t	pid;
} * PidList;

/* Serialize access to PidList. */
static pthread_mutex_t ListMutex = PTHREAD_MUTEX_INITIALIZER;

static void	close_cleanup(void *);

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
	int    fd, twoway;
	spine_pid_t  pid;
	char   *argv[4];
	char   *command_copy;
	char   shell_cmd[] = "sh";
	char   shell_flag[] = "-c";
	int    cancel_state;
	char   error_buffer[256];
	posix_spawnattr_t attr;
	int    attr_initialized = 0;
	sigset_t default_sigs;
	sigset_t empty_mask;
	char **child_env = NULL;

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

	if (spine_process_pipe(pdes) < 0)
		return -1;

	/* Disable thread cancellation from this point forward. */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);

	if ((cur = malloc(sizeof(struct pid))) == NULL) {
		(void)spine_process_close_fd(pdes[0]);
		(void)spine_process_close_fd(pdes[1]);
		pthread_setcancelstate(cancel_state, NULL);
		return -1;
	}

	if ((command_copy = strdup(command)) == NULL) {
		(void)spine_process_close_fd(pdes[0]);
		(void)spine_process_close_fd(pdes[1]);
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
		(void)spine_process_close_fd(pdes[0]);
		(void)spine_process_close_fd(pdes[1]);
		pthread_mutex_unlock(&ListMutex);
		free(command_copy);
		free(cur);
		pthread_setcancelstate(cancel_state, NULL);
		return -1;
	}

	/* Reset signal dispositions in the child so spine's ignores/handlers do
	 * not leak into the script. Without this, SIGPIPE-ignoring spine
	 * propagates to a child /bin/sh that silently swallows broken pipes. */
	if (posix_spawnattr_init(&attr) == 0) {
		attr_initialized = 1;
		sigfillset(&default_sigs);
		posix_spawnattr_setsigdefault(&attr, &default_sigs);
		sigemptyset(&empty_mask);
		posix_spawnattr_setsigmask(&attr, &empty_mask);
		posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK);
	}

	if (*type == 'r') {
		posix_spawn_file_actions_addclose(&fa, pdes[0]);
		if (pdes[1] != STDOUT_FILENO) {
			posix_spawn_file_actions_adddup2(&fa, pdes[1], STDOUT_FILENO);
			posix_spawn_file_actions_addclose(&fa, pdes[1]);
			if (twoway)
				posix_spawn_file_actions_adddup2(&fa, STDOUT_FILENO, STDIN_FILENO);
		} else if (twoway && (pdes[1] != STDIN_FILENO)) {
			posix_spawn_file_actions_adddup2(&fa, pdes[1], STDIN_FILENO);
		}
	} else {
		if (pdes[0] != STDIN_FILENO) {
			posix_spawn_file_actions_adddup2(&fa, pdes[0], STDIN_FILENO);
			posix_spawn_file_actions_addclose(&fa, pdes[0]);
		}
		posix_spawn_file_actions_addclose(&fa, pdes[1]);
	}

	/* Close all other pipes in the child (Posix.2 requirement). */
	for (p = PidList; p; p = p->next)
		posix_spawn_file_actions_addclose(&fa, p->fd);

	/* Spawn the child process with retry on EAGAIN/ENOMEM. */
	const char *spawn_shell = "/bin/sh";

	child_env = spine_build_child_env();
	if (child_env == NULL) {
		SPINE_LOG(("ERROR: SCRIPT: failed to build child env"));
		posix_spawn_file_actions_destroy(&fa);
		if (attr_initialized) {
			posix_spawnattr_destroy(&attr);
		}
		(void)spine_process_close_fd(pdes[0]);
		(void)spine_process_close_fd(pdes[1]);
		pthread_mutex_unlock(&ListMutex);
		free(command_copy);
		free(cur);
		pthread_setcancelstate(cancel_state, NULL);
		return -1;
	}

	int spawn_err;
	spawn_err = spine_process_spawn_retry(&pid, spawn_shell, &fa,
		attr_initialized ? &attr : NULL,
		argv, child_env, 3, 50000);

	if (spawn_err != 0) {
		SPINE_LOG(("ERROR: SCRIPT: posix_spawn failed: %s", spine_platform_error_string(spawn_err, error_buffer, sizeof(error_buffer))));
		posix_spawn_file_actions_destroy(&fa);
		if (attr_initialized) {
			posix_spawnattr_destroy(&attr);
		}
		free(child_env);
		(void)spine_process_close_fd(pdes[0]);
		(void)spine_process_close_fd(pdes[1]);
		pthread_mutex_unlock(&ListMutex);
		free(command_copy);
		pthread_setcancelstate(cancel_state, NULL);
		return -1;
	}

	posix_spawn_file_actions_destroy(&fa);
	if (attr_initialized) {
		posix_spawnattr_destroy(&attr);
	}
	/* child_env points into environ for the borrowed strings, so free only
	 * the outer array. posix_spawn has already copied the env into the child. */
	free(child_env);

	/* Parent. */
	if (*type == 'r') {
		fd = pdes[0];
		(void)spine_process_close_fd(pdes[1]);
	}else {
		fd = pdes[1];
		(void)spine_process_close_fd(pdes[0]);
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
	spine_pid_t	pid = 0;

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
	spine_pid_t	pid;

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
	(void)spine_process_close_fd(fd);

	cur->fd = -1;		/* Prevent the fd being closed twice. */

	if (spine_process_wait(cur->pid, &pstat) != 0) {
		pid = -1;
	} else {
		pid = cur->pid;
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
		(void)spine_process_close_fd(cur->fd);
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
