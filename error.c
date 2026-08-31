/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU Lesser General Public              |
 | License as published by the Free Software Foundation; either            |
 | version 2.1 of the License, or (at your option) any later version. 	   |
 |                                                                         |
 | This program is distributed in the hope that it will be useful,         |
 | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
 | GNU Lesser General Public License for more details.                     |
 |                                                                         |
 | You should have received a copy of the GNU Lesser General Public        |
 | License along with this library; if not, write to the Free Software     |
 | Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA           |
 | 02110-1301, USA                                                         |
 |                                                                         |
 +-------------------------------------------------------------------------+
 | spine: a backend data gatherer for cacti                                |
 +-------------------------------------------------------------------------+
 | This poller would not have been possible without:                       |
 |   - Larry Adams (current development and enhancements)                  |
 |   - Rivo Nurges (rrd support, mysql poller cache, misc functions)       |
 |   - RTG (core poller code, pthreads, snmp, autoconf examples)           |
 |   - Brady Alleman/Doug Warner (threading ideas, implementation details) |
 +-------------------------------------------------------------------------+
 | - Cacti - http://www.cacti.net/                                         |
 +-------------------------------------------------------------------------+
*/

/* These functions handle simple signal handling functions for Spine.  It was
   written to handle specifically issues with the Solaris threading model in
   version 2.8.
*/

#include "common.h"
#include "spine.h"

/*! \fn static void signal_write(const char *text)
 *  \brief writes a NUL terminated message to stderr from a signal handler
 *
 */
static void signal_write(const char *text) {
	size_t length = 0;

	while (text[length] != '\0') {
		length++;
	}

	while (length > 0) {
		ssize_t written = write(STDERR_FILENO, text, length);

		if (written <= 0) {
			if (written < 0 && errno == EINTR) {
				continue;
			}

			return;
		}

		text   += written;
		length -= (size_t) written;
	}
}

/*! \fn static void signal_write_number(long long value)
 *  \brief writes a number to stderr from a signal handler
 *
 */
static void signal_write_number(long long value) {
	char   digits[24];
	size_t index = sizeof(digits) - 1;
	unsigned long long magnitude = (unsigned long long) value;

	digits[index] = '\0';

	do {
		digits[--index] = (char) ('0' + (magnitude % 10));
		magnitude /= 10;
	} while (magnitude > 0 && index > 0);

	signal_write(digits + index);
}

/*! \fn static void spine_signal_handler(int spine_signal)
 *  \brief interrupts the os default signal handler as appropriate.
 *
 *  Only async-signal-safe calls belong here.  A SIGSEGV usually follows heap
 *  corruption, so formatting a log timestamp with strftime would take the
 *  malloc arena lock from the fault handler and hang the poller instead of
 *  killing it.  time() is on the POSIX async-signal-safe list, so the stamp is
 *  written as epoch seconds and the reader converts it.
 */
static void spine_signal_handler(int spine_signal) {
	const char *message = NULL;
	int saved_errno = errno;

	signal(spine_signal, SIG_DFL);

	set.exit_code = spine_signal;

	switch (spine_signal) {
		case SIGABRT:
			message = "FATAL: Spine Interrupted by Abort Signal\n";
			break;
		case SIGINT:
			message = "FATAL: Spine Interrupted by Console Operator\n";
			break;
		case SIGSEGV:
			message = "FATAL: Spine Encountered a Segmentation Fault\n";
			break;
		case SIGBUS:
			message = "FATAL: Spine Encountered a Bus Error\n";
			break;
		case SIGFPE:
			message = "FATAL: Spine Encountered a Floating Point Exception\n";
			break;
		case SIGQUIT:
			message = "FATAL: Spine Encountered a Keyboard Quit Command\n";
			break;
		case SIGPIPE:
			message = "FATAL: Spine Encountered a Broken Pipe\n";
			break;
		default:
			break;
	}

	signal_write("[");
	signal_write_number((long long) time(NULL));
	signal_write("] ");

	if (message != NULL) {
		signal_write(message);
	} else {
		signal_write("FATAL: Spine Encountered An Unhandled Exception Signal Number: '");
		signal_write_number(spine_signal);
		signal_write("'\n");
	}

	if (spine_signal == SIGSEGV) {
		_exit(1);
	}

	errno = saved_errno;
}

static int spine_fatal_signals[] = {
	SIGINT,
	SIGPIPE,
	SIGSEGV,
	SIGBUS,
	SIGFPE,
	SIGQUIT,
	SIGSYS,
	SIGABRT,
	0
};

/*! \fn void install_spine_signal_handler(void)
 *  \brief installs the spine signal handler to stop certain calls from
 *         abending Spine.
 *
 */
void install_spine_signal_handler(void) {
	/* Set a handler for any fatal signal not already handled */
	int i;
	struct sigaction sa;
	void (*ohandler)(int);

	for (i=0; spine_fatal_signals[i]; ++i) {
		sigaction(spine_fatal_signals[i], NULL, &sa);
		if (sa.sa_handler == SIG_DFL) {
			sa.sa_handler = spine_signal_handler;
			sigemptyset(&sa.sa_mask);
			sa.sa_flags = SA_RESTART;
			sigaction(spine_fatal_signals[i], &sa, NULL);
		}
	}

	for (i=0; spine_fatal_signals[i]; ++i) {
		ohandler = signal(spine_fatal_signals[i], spine_signal_handler);
		if (ohandler != SIG_DFL) {
			signal(spine_fatal_signals[i], ohandler);
		}
	}

	return;
}

/*! \fn void uninstall_spine_signal_handler(void)
 *  \brief uninstalls the spine signal handler.
 *
 */
void uninstall_spine_signal_handler(void) {
	/* Remove a handler for any fatal signal handled */
	int i;
	struct sigaction sa;
	void (*ohandler)(int);

	for (i=0; spine_fatal_signals[i]; ++i) {
		sigaction(spine_fatal_signals[i], NULL, &sa);
		if (sa.sa_handler == spine_signal_handler) {
			sa.sa_handler = SIG_DFL;
			sigaction(spine_fatal_signals[i], &sa, NULL);
		}
	}

	for ( i=0; spine_fatal_signals[i]; ++i ) {
		ohandler = signal(spine_fatal_signals[i], SIG_DFL);
		if (ohandler != spine_signal_handler) {
			signal(spine_fatal_signals[i], ohandler);
		}
	}
}
