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

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include "platform/descriptor.h"
#include "internal/constants.h"
#include "log/log.h"

int file_exists(const char *filename) {
	struct stat file_stat;

	if (stat(filename, &file_stat)) {
		return FALSE;
	} else {
		return TRUE;
	}
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

int spine_dup_cloexec(int fd) {
	int duplicate;
	int saved_errno;

	duplicate = dup(fd);
	if (duplicate < 0)
		return -1;

	if (spine_set_cloexec(duplicate) != 0) {
		saved_errno = errno;
		(void) close(duplicate);
		errno = saved_errno;
		return -1;
	}

	return duplicate;
}
