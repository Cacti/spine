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

#ifndef SPINE_NFT_POPEN_H
#define SPINE_NFT_POPEN_H

#include <spawn.h>
/******************************************************************************
 ex: set tabstop=4 shiftwidth=4 autoindent:
 *
 * (C) Copyright Xenadyne, Inc. 2002  All rights reserved.
 *
 * Permission to use, copy, modify and distribute this software for
 * any purpose and without fee is hereby granted, provided that the
 * above copyright notice appears in all copies.
 *
 * XENADYNE INC DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.
 * IN NO EVENT SHALL XENADYNE BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM THE
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * File:    nft_popen.h
 *
 * PURPOSE
 *
 * Thread-safe substitute for popen() that doesn't use stdio streams.
 *
 ******************************************************************************
 */

/*!
 *  The nft_popen() function forks a command in a child process, and returns
 *  a pipe that is connected to the child's standard input and output. It is
 *  like the standard popen() call, except that it returns the file descriptor,
 *  instead of a stdio stream created by fdopen(). The file descriptor can be
 *  used with select() or poll(), or the caller can use fdopen() if a stdio
 *  FILE* is preferable.
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
 */
extern int	nft_popen(const char * command, const char * mode);

/*!
 *  nft_pchild
 *
 *  Get the pid of the child process for an fd created by ntf_popen().
 *
 *  On success, the pid of the child process is returned.
 *  On failure, nft_pchild() returns -1, with errno set to:
 *
 *    EBADF	The fd is not an active nft_popen() file descriptor.
 */
extern int	nft_pchild(int fd);

/*!
 *  nft_pclose
 *
 *  Close the pipe and wait for the status of the child process.
 *
 *  On success, the exit status of the child process is returned.
 *  On failure, nft_pclose() returns -1, with errno set to:
 *
 *	EBADF	The fd is not an active popen() file descriptor.
 *	ETIMEDOUT	The child outlived the TERM/KILL budgets.
 *	otherwise	The errno reported by waitpid().
 */
extern int	nft_pclose(int fd);

/*!
 *  spine_set_cloexec
 *
 *  Mark a descriptor close-on-exec.
 *
 *  Returns 0 on success, -1 on failure with errno set by fcntl().
 */
extern int	spine_set_cloexec(int fd);

/*!
 *  spine_open_pipe_cloexec
 *
 *  Open a pipe whose descriptors are not inherited across exec. Spine spawns
 *  children from several threads, so a descriptor left inheritable is held by
 *  an unrelated child and the reader never sees EOF.
 *
 *  Returns TRUE on success. On failure the descriptors are closed and FALSE is
 *  returned, so the caller owns nothing.
 */
extern int	spine_open_pipe_cloexec(int pdes[2]);

/* Initialize spawn attributes that restore SIGPIPE's default disposition in
 * posix_spawned children while Spine catches SIGPIPE in the parent. */
extern int	spine_spawnattr_sigpipe_default(posix_spawnattr_t *attr);

/*!
 *  spine_reap_child_bounded
 *
 *  Reap a child with WNOHANG, sleeping between attempts, so a wedged script
 *  cannot pin a poller thread indefinitely.
 *
 *  Returns 0 when the child was reaped, 1 when it is still running after
 *  attempts, and -1 on a waitpid() error other than EINTR or ECHILD.
 */
extern int	spine_reap_child_bounded(pid_t pid, int *pstat, int attempts);

/*!
 *  The cap on parked pids. Past it a child is logged and dropped, because an
 *  unbounded list would trade a pid leak for a memory leak.
 */
#define NFT_ABANDONED_MAX 64

/*!
 *  nft_abandon_child
 *
 *  Record a child that outlived nft_pclose()'s kill budget. Nothing else in
 *  spine reaps, so a dropped child would stay a zombie for the daemon's
 *  lifetime; parked pids are swept by the scheduler and on the next script
 *  poll. The pid and reason are logged either way.
 */
extern void	nft_abandon_child(pid_t pid, const char *reason);

/*!
 *  nft_abandoned_pending
 *
 *  Sweep the parked pids with WNOHANG and return how many are still running.
 *  Zero means nothing is leaking.
 */
extern int	nft_abandoned_pending(void);

#endif /* SPINE_NFT_POPEN_H */
