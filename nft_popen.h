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
 *	ECHILD	waitpid() failed.
 */
extern int	nft_pclose(int fd);
