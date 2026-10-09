/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU Lesser General Public              |
 | License as published by the Free Software Foundation; either            |
 | version 2.1 of the License, or (at your option) any later version.      |
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

#include "common.h"
#include "spine.h"
#include "regex.h"
#define SPINE_STRINGIFY_INNER(value) #value
#define SPINE_STRINGIFY(value) SPINE_STRINGIFY_INNER(value)

/* pthread storage keeps the borrowed match valid without requiring C11 TLS.
 * Each polling thread owns its buffer, which is freed when the thread exits. */
static pthread_key_t regex_result_key;
static pthread_once_t regex_result_once = PTHREAD_ONCE_INIT;

static void initialize_regex_result_key(void) {
	if (pthread_key_create(&regex_result_key, free) != 0) {
		set.exit.exit_code = EXIT_FAILURE;
		die("ERROR: Unable to create thread-local regex storage");
	}
}

static char *regex_result_buffer(void) {
	if (pthread_once(&regex_result_once, initialize_regex_result_key) != 0) {
		set.exit.exit_code = EXIT_FAILURE;
		die("ERROR: Unable to initialize thread-local regex storage");
	}
	char *buffer = pthread_getspecific(regex_result_key);
	if (buffer == NULL) {
		buffer = malloc(RESULTS_BUFFER);
		if (buffer == NULL) die("ERROR: Fatal malloc error: regex result buffer!");
		if (pthread_setspecific(regex_result_key, buffer) != 0) {
			free(buffer);
			set.exit.exit_code = EXIT_FAILURE;
			die("ERROR: Unable to retain thread-local regex storage");
		}
	}
	return buffer;
}

char *regex_replace(const char *exp, char *value) {
	regex_t regex;
	int reti;
	char *msgbuf = NULL;

	/* Stored output_regex values use the historical basic-regex dialect. */
	reti = regcomp(&regex, exp, 0);
	if (reti) {
		return value;
	}

	/* Execute regular expression */
	regmatch_t matches[MAX_MATCHES];
	reti = regexec(&regex, value, MAX_MATCHES, matches, 0);
	if (!reti) {
		// regex matched
		size_t length = (size_t) (matches[0].rm_eo - matches[0].rm_so);
		if (length >= RESULTS_BUFFER) {
			regfree(&regex);
			return value;
		}
		msgbuf = regex_result_buffer();
		memcpy(msgbuf, value + matches[0].rm_so, length);
		msgbuf[length] = '\0';
	}

	/* Free memory allocated to the pattern buffer by regcomp() */
	regfree(&regex);

	return reti ? value : msgbuf;
}

int format_spine_capabilities(char *output, size_t output_size,
	const char *auth_protocols, const char *priv_protocols) {
	int written;

	if (output == NULL || output_size == 0 ||
		auth_protocols == NULL || priv_protocols == NULL) {
		return FALSE;
	}

	written = snprintf(output, output_size,
		"{ authProtocols: \"%." SPINE_STRINGIFY(CAPABILITY_PROTOCOL_LIST_MAX) "s\", privProtocols: \"%." SPINE_STRINGIFY(CAPABILITY_PROTOCOL_LIST_MAX) "s\" }",
		auth_protocols, priv_protocols);

	return written >= 0 && (size_t) written < output_size;
}
