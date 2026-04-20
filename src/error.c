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

/*! \fn static void spine_signal_handler(int spine_signal)
 *  \brief Async-signal-safe fatal handler.
 *
 * Must not call malloc / stdio / strftime / exit; the handler may be
 * entered with libc locks held (SIGSEGV inside the heap) or the stdio
 * lock (SIGINT mid-fprintf). Writes a precomputed one-line message to
 * stderr via write(2), then _exit(128 + sig) so atexit and the stdio
 * buffers are not flushed from a potentially corrupt state.
 *
 * Signal numbers are not portable compile-time constants so the table
 * is initialised once at install time rather than as a designated
 * initialiser.
 */
/* AS-safe integer -> decimal string. Returns number of bytes written
 * into buf (without NUL). buf must hold at least 21 bytes. */
static size_t spine_as_safe_u64_to_dec(unsigned long long v, char *buf) {
	char tmp[21];
	size_t n = 0;
	if (v == 0) {
		buf[0] = '0';
		return 1;
	}
	while (v > 0 && n < sizeof(tmp)) {
		tmp[n++] = (char)('0' + (v % 10));
		v /= 10;
	}
	for (size_t i = 0; i < n; i++) {
		buf[i] = tmp[n - 1 - i];
	}
	return n;
}

static void spine_signal_handler(int spine_signal) {
	signal(spine_signal, SIG_DFL);

	set.exit_code = spine_signal;

	static const char msg_abrt[] = " FATAL: Spine Interrupted by Abort Signal\n";
	static const char msg_int[]  = " FATAL: Spine Interrupted by Console Operator\n";
	static const char msg_segv[] = " FATAL: Spine Encountered a Segmentation Fault\n";
	static const char msg_bus[]  = " FATAL: Spine Encountered a Bus Error\n";
	static const char msg_fpe[]  = " FATAL: Spine Encountered a Floating Point Exception\n";
	static const char msg_quit[] = " FATAL: Spine Encountered a Keyboard Quit Command\n";
	static const char msg_pipe[] = " FATAL: Spine Encountered a Broken Pipe\n";
	static const char msg_sys[]  = " FATAL: Spine Encountered a Bad System Call\n";
	static const char msg_dflt[] = " FATAL: Spine Encountered An Unhandled Exception Signal\n";

	const char *msg = msg_dflt;
	size_t      len = sizeof(msg_dflt) - 1;

	switch (spine_signal) {
		case SIGABRT: msg = msg_abrt; len = sizeof(msg_abrt) - 1; break;
		case SIGINT:  msg = msg_int;  len = sizeof(msg_int)  - 1; break;
		case SIGSEGV: msg = msg_segv; len = sizeof(msg_segv) - 1; break;
		case SIGBUS:  msg = msg_bus;  len = sizeof(msg_bus)  - 1; break;
		case SIGFPE:  msg = msg_fpe;  len = sizeof(msg_fpe)  - 1; break;
		case SIGQUIT: msg = msg_quit; len = sizeof(msg_quit) - 1; break;
		case SIGPIPE: msg = msg_pipe; len = sizeof(msg_pipe) - 1; break;
		case SIGSYS:  msg = msg_sys;  len = sizeof(msg_sys)  - 1; break;
	}

	/* Emit wall-clock seconds-since-epoch (time(2) is AS-safe) so the
	 * operator can correlate the crash with journalctl / syslog. The
	 * full strftime path would require non-AS-safe localtime + strftime;
	 * a raw epoch avoids that and is trivial to feed to `date -d @SECS`. */
	char tsbuf[32];
	time_t now = time(NULL);
	size_t tslen = spine_as_safe_u64_to_dec((unsigned long long)now, tsbuf);

	(void)!write(STDERR_FILENO, tsbuf, tslen);
	(void)!write(STDERR_FILENO, msg, len);

	/* 128 + signo is the conventional shell exit code for a signal death. */
	_exit(128 + spine_signal);
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
