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

#include "internal/common.h"
#include "app/spine.h"
#include "process/process_internal.h"
#include <spawn.h>
#include <fcntl.h>
#include <sys/wait.h>




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
		(void) close(pdes[0]);
		(void) close(pdes[1]);

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
	int eintr_budget;
	int fast_attempts;
	double deadline;
	pid_t waited;

	if (pstat == NULL) {
		return -1;
	}

	if (attempts <= 0) return 1;
	fast_attempts = attempts < NFT_PCLOSE_SPIN_ATTEMPTS ? attempts : NFT_PCLOSE_SPIN_ATTEMPTS;
	/* BSD kernels may round a 200 us sleep to an entire scheduler tick.
	 * Bound elapsed grace time as well as syscall attempts. */
	deadline = spine_monotonic_time() +
		((double) fast_attempts * NFT_PCLOSE_SPIN_USEC +
			(double) (attempts - fast_attempts) * NFT_PCLOSE_REAP_USEC) /
			1000000.0;

	for (attempt = 0; attempt < attempts; attempt++) {
		/* Bounded so a stream of caught signals cannot spin this call
		 * forever instead of returning within its attempt budget. */
		eintr_budget = 1000;
		do {
			waited = waitpid(pid, pstat, WNOHANG);
		} while (waited < 0 && errno == EINTR && --eintr_budget > 0 && spine_monotonic_time() < deadline);

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

		if (spine_monotonic_time() >= deadline) return 1;

/* The delay is load-bearing: without it the attempts are spent in
		   nanoseconds and the caller's kill lands before the child can exit.

		   Starting at the full 50ms charged that to every script that exits a
		   moment after closing stdout, which is the common case for anything
		   that flushes or tears down an interpreter. Spin briefly first, then
		   settle, so a caller that opts into this bounded wait does not pay
		   the full interval on every reap.

		   usleep() is skipped rather than replaced under SOLAR_THREAD, same as
		   everywhere else in the tree - a flat sleep(1) here would blow the
		   ~20ms budget nft_pclose() relies on (attempts * 1s), so an
		   un-delayed retry is the correct bounded behavior on that platform. */
#ifndef SOLAR_THREAD
		if (attempt < NFT_PCLOSE_SPIN_ATTEMPTS) {
			usleep(NFT_PCLOSE_SPIN_USEC);
		} else {
			usleep(NFT_PCLOSE_REAP_USEC);
		}
#endif
	}

	return 1;
}
