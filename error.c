/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2024 The Cacti Group                                 |
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
 |   - Brady Alleman/Doug Warner (threading ideas, implimentation details) |
 +-------------------------------------------------------------------------+
 | - Cacti - http://www.cacti.net/                                         |
 +-------------------------------------------------------------------------+
*/

/* These functions handle simple singal handling functions for Spine.  It was
   written to handle specifically issues with the Solaris threading model in
   version 2.8.
*/

#include "common.h"
#include "spine.h"

/*! \fn static void signal_write(const char *message, size_t message_length)
 *  \brief emits a diagnostic from inside a signal handler.
 *
 *  Only async-signal-safe calls are permitted here, and a short or failed
 *  write cannot be reported through any other channel, so the result is
 *  deliberately discarded.
 */
static void signal_write(const char *message, size_t message_length) {
	ssize_t written;

	written = write(STDERR_FILENO, message, message_length);

	(void) written;
}

/*! \fn static void spine_signal_handler(int spine_signal)
 *  \brief interupts the os default signal handler as appropriate.
 *
 */
static void spine_signal_handler(int spine_signal) {
	static const char unhandled[] = "FATAL: Spine interrupted by an unhandled signal, number ";
	const char *message = NULL;
	size_t message_length = 0;
	int unrecoverable = FALSE;
	char digits[16];
	int offset;
	int number;

	signal(spine_signal, SIG_DFL);

	set.exit_code = spine_signal;

	switch (spine_signal) {
		case SIGABRT:
			message = "FATAL: Spine interrupted by abort signal\n";
			message_length = sizeof("FATAL: Spine interrupted by abort signal\n") - 1;
			break;
		case SIGINT:
			message = "FATAL: Spine interrupted by console operator\n";
			message_length = sizeof("FATAL: Spine interrupted by console operator\n") - 1;
			break;
		case SIGSEGV:
			message = "FATAL: Spine encountered a segmentation fault\n";
			message_length = sizeof("FATAL: Spine encountered a segmentation fault\n") - 1;
			unrecoverable = TRUE;
			break;
		case SIGBUS:
			message = "FATAL: Spine encountered a bus error\n";
			message_length = sizeof("FATAL: Spine encountered a bus error\n") - 1;
			unrecoverable = TRUE;
			break;
		case SIGFPE:
			message = "FATAL: Spine encountered a floating point exception\n";
			message_length = sizeof("FATAL: Spine encountered a floating point exception\n") - 1;
			unrecoverable = TRUE;
			break;
		case SIGQUIT:
			message = "FATAL: Spine encountered a keyboard quit command\n";
			message_length = sizeof("FATAL: Spine encountered a keyboard quit command\n") - 1;
			break;
		case SIGPIPE:
			message = "FATAL: Spine encountered a broken pipe\n";
			message_length = sizeof("FATAL: Spine encountered a broken pipe\n") - 1;
			break;
		default:
			/* render the number by hand; snprintf is not async-signal-safe */
			offset = sizeof(digits);
			digits[--offset] = '\n';
			number = spine_signal;

			do {
				digits[--offset] = (char) ('0' + (number % 10));
				number /= 10;
			} while (number > 0 && offset > 0);

			signal_write(unhandled, sizeof(unhandled) - 1);
			signal_write(digits + offset, sizeof(digits) - offset);
			break;
	}

	if (message != NULL) {
		signal_write(message, message_length);
	}

	/* returning would resume the faulting instruction, so these cannot be
	   handed back to the interrupted thread */
	if (unrecoverable) {
		_exit(1);
	}
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
