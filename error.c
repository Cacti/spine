/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2002-2006 The Cacti Group                                 |
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
 | cactid: a backend data gatherer for cacti                               |
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

/* These functions handle simple singal handling functions for Cactid.  It was
   written to handle specifically issues with the Solaris threading model in
   version 2.8.
*/

#include "common.h"
#include "cactid.h"

/*! \fn static void cactid_signal_handler(int cactid_signal)
 *  \brief interupts the os default signal handler as appropriate.
 *
 */
static void cactid_signal_handler(int cactid_signal) {
	signal(cactid_signal, SIG_DFL);

	set.exit_code = cactid_signal;

	switch (cactid_signal) {
		case SIGINT:
			die("FATAL: Cactid Interrupted by Console Operator");
			break;
		case SIGSEGV:
			die("FATAL: Cactid Encountered a Segmentation Fault");
			break;
		case SIGBUS:
			die("FATAL: Cactid Encountered a Bus Error");
			break;
		case SIGFPE:
			die("FATAL: Cactid Encountered a Floating Point Exception");
			break;
		case SIGQUIT:
			die("FATAL: Cactid Encountered a Keyboard Quit Command");
			break;
		case SIGPIPE:
			die("FATAL: Cactid Encountered a Broken Pipe");
			break;
		default:
			die("FATAL: Cactid Encountered An Unhandled Exception Signal Number: '%d'", cactid_signal);
			break;
	}
}

static int cactid_fatal_signals[] = {
	SIGINT,
	SIGSEGV,
	SIGBUS,
	SIGFPE,
	SIGQUIT,
	0
};

/*! \fn void install_cactid_signal_handler(void)
 *  \brief installs the cactid signal handler to stop certain calls from 
 *         abending Cactid.
 *
 */
void install_cactid_signal_handler(void) {
	/* Set a handler for any fatal signal not already handled */
	int i;
	struct sigaction action;

	for ( i=0; cactid_fatal_signals[i]; ++i ) {
		sigaction(cactid_fatal_signals[i], NULL, &action);
		if ( action.sa_handler == SIG_DFL ) {
			action.sa_handler = cactid_signal_handler;
			sigaction(cactid_fatal_signals[i], &action, NULL);
		}
	}
	#ifdef SOLAR_THREAD
	/* Set SIGALRM to be ignored -- necessary on Solaris */
	sigaction(SIGALRM, NULL, &action);
	if ( action.sa_handler == SIG_DFL ) {
		action.sa_handler = SIG_IGN;
		sigaction(SIGALRM, &action, NULL);
	}
	#endif
	void (*ohandler)(int);

	for ( i=0; cactid_fatal_signals[i]; ++i ) {
		ohandler = signal(cactid_fatal_signals[i], cactid_signal_handler);
		if ( ohandler != SIG_DFL ) {
			signal(cactid_fatal_signals[i], ohandler);
		}
	}
	return;
}

/*! \fn void uninstall_cactid_signal_handler(void)
 *  \brief uninstalls the cactid signal handler.
 *
 */
void uninstall_cactid_signal_handler(void) {
	/* Remove a handler for any fatal signal handled */
	int i;
	struct sigaction action;

	for ( i=0; cactid_fatal_signals[i]; ++i ) {
		sigaction(cactid_fatal_signals[i], NULL, &action);
		if ( action.sa_handler == cactid_signal_handler ) {
			action.sa_handler = SIG_DFL;
			sigaction(cactid_fatal_signals[i], &action, NULL);
		}
	}

	void (*ohandler)(int);

	for ( i=0; cactid_fatal_signals[i]; ++i ) {
		ohandler = signal(cactid_fatal_signals[i], SIG_DFL);
		if ( ohandler != cactid_signal_handler ) {
			signal(cactid_fatal_signals[i], ohandler);
		}
	}
}
