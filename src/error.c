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

#include <unistd.h>

/* POSIX async-signal-safe writes and _exit need <signal.h>/<unistd.h>;
 * both are already pulled in via common.h / spine.h. */

/* Pre-formatted per-signal fatal messages. Building them inside the signal
 * handler would require calls to sprintf/localtime/strftime, none of which
 * are async-signal-safe. Populate once at startup via
 * spine_signal_handler_init() then write(2) the chosen entry from the
 * handler. Max signal index for the table: SIGSYS on Linux sits at 31,
 * but BSD uses values up to 32 and older stacks fit in 32. Size for 64
 * to cover every real-world kernel without heap allocation. */
#define SPINE_SIG_MSG_MAX 64
#define SPINE_SIG_MSG_LEN 96

static char     spine_sig_msgs[SPINE_SIG_MSG_MAX][SPINE_SIG_MSG_LEN];
static size_t   spine_sig_lens[SPINE_SIG_MSG_MAX];
static char     spine_sig_default_msg[SPINE_SIG_MSG_LEN];
static size_t   spine_sig_default_len;

static int spine_fatal_signals[] = {
	SIGINT,
	SIGSEGV,
	SIGBUS,
	SIGFPE,
	SIGQUIT,
	SIGSYS,
	SIGABRT,
	0
};

static void spine_sig_set(int signo, const char *text) {
	if (signo <= 0 || signo >= SPINE_SIG_MSG_MAX) {
		return;
	}
	int n = snprintf(spine_sig_msgs[signo], SPINE_SIG_MSG_LEN, "%s", text);
	if (n < 0) {
		spine_sig_lens[signo] = 0;
		return;
	}
	spine_sig_lens[signo] = ((size_t)n < SPINE_SIG_MSG_LEN) ? (size_t)n : (SPINE_SIG_MSG_LEN - 1);
}

/*! \fn void spine_signal_handler_init(void)
 *  \brief Pre-format the fatal-signal message table. Call before
 *         install_spine_signal_handler() so the table is populated before
 *         any signal delivery.
 */
void spine_signal_handler_init(void) {
	spine_sig_set(SIGABRT, "FATAL: Spine Interrupted by Abort Signal\n");
	spine_sig_set(SIGINT,  "FATAL: Spine Interrupted by Console Operator\n");
	spine_sig_set(SIGSEGV, "FATAL: Spine Encountered a Segmentation Fault\n");
	spine_sig_set(SIGBUS,  "FATAL: Spine Encountered a Bus Error\n");
	spine_sig_set(SIGFPE,  "FATAL: Spine Encountered a Floating Point Exception\n");
	spine_sig_set(SIGQUIT, "FATAL: Spine Encountered a Keyboard Quit Command\n");
	spine_sig_set(SIGSYS,  "FATAL: Spine Encountered an Unhandled System Call\n");

	int n = snprintf(spine_sig_default_msg, SPINE_SIG_MSG_LEN, "FATAL: Spine Encountered an Unhandled Fatal Signal\n");
	if (n < 0) {
		spine_sig_default_len = 0;
	} else {
		spine_sig_default_len = ((size_t)n < SPINE_SIG_MSG_LEN) ? (size_t)n : (SPINE_SIG_MSG_LEN - 1);
	}
}

/*! \fn static void spine_signal_handler(int spine_signal)
 *  \brief Async-signal-safe fatal handler.
 *
 *  Only POSIX-async-signal-safe primitives are used: write(2) to emit a
 *  pre-formatted message and _exit(2) for the hard-abort path on memory
 *  faults. stdio, time(3), localtime(3), strftime(3), and exit(3) are all
 *  unsafe to call from a signal handler.
 */
static void spine_signal_handler(int spine_signal) {
	const char *msg;
	size_t len;

	if (spine_signal > 0 && spine_signal < SPINE_SIG_MSG_MAX &&
	    spine_sig_lens[spine_signal] > 0) {
		msg = spine_sig_msgs[spine_signal];
		len = spine_sig_lens[spine_signal];
	} else {
		msg = spine_sig_default_msg;
		len = spine_sig_default_len;
	}

	/* write(2) return value is deliberately ignored: the process is
	 * already terminating and there is nothing useful to do on EINTR. */
	if (len > 0) {
		(void)!write(STDERR_FILENO, msg, len);
	}

	/* Memory-corruption signals leave the runtime in an undefined state.
	 * Using exit(3) would run atexit handlers, flush stdio, and hit
	 * libc allocators that may already be mid-update. _exit(2) is the
	 * async-signal-safe abort path. 128 + signo is the conventional
	 * shell exit encoding for signal-terminated processes. */
	if (spine_signal == SIGSEGV || spine_signal == SIGBUS ||
	    spine_signal == SIGFPE  || spine_signal == SIGABRT) {
		_exit(128 + spine_signal);
	}
}

/*! \fn void install_spine_signal_handler(void)
 *  \brief installs the spine signal handler to stop certain calls from
 *         abending Spine.
 *
 */
void install_spine_signal_handler(void) {
	/* Set a handler for any fatal signal not already handled */
	int i;
	struct sigaction sa;

	/* A poll script closing stdout early used to terminate spine via the
	 * default SIGPIPE action. Ignore it process-wide: the write(2) call
	 * simply returns EPIPE and the caller can recover. */
	signal(SIGPIPE, SIG_IGN);

	for (i=0; spine_fatal_signals[i]; ++i) {
		sigaction(spine_fatal_signals[i], NULL, &sa);
		if (sa.sa_handler == SIG_DFL) {
			sa.sa_handler = spine_signal_handler;
			sigemptyset(&sa.sa_mask);
			/* No SA_RESTART: fatal handler should not try to resume
			 * interrupted syscalls in a half-broken runtime. */
			sa.sa_flags = 0;
			sigaction(spine_fatal_signals[i], &sa, NULL);
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

	for (i=0; spine_fatal_signals[i]; ++i) {
		sigaction(spine_fatal_signals[i], NULL, &sa);
		if (sa.sa_handler == spine_signal_handler) {
			sa.sa_handler = SIG_DFL;
			sigemptyset(&sa.sa_mask);
			sa.sa_flags = 0;
			sigaction(spine_fatal_signals[i], &sa, NULL);
		}
	}
}
