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
 *
 * COMMAND-LINE PARAMETERS
 *
 * -h | --help
 * -v | --version
 *
 *	Show a brief help listing, then exit.
 *
 * -C | --conf=F
 *
 *	Provide the name of the Spine configuration file, which contains
 *	the parameters for connecting to the database. In the absence of
 *	this, it searches in order: the current directory, /etc/,
 *	/etc/cacti/, and ../etc/ for a file named spine.conf.
 *
 * -f | --first=ID
 *
 *	Start polling with device <ID> (else starts at the beginning)
 *
 * -l | --last=ID
 *
 *	Stop polling after device <ID> (else ends with the last one)
 *
 * -m | --mibs
 *
 *	Collect all system mibs this pass
 *
 * -N | --mode=online|offline|recovery
 *
 *	For remote pollers, the polling mode.  The default is 'online'
 *
 * -H | --hostlist="hostid1,hostid2,hostid3,...,hostidn"
 *
 *	Override the expected first host, last host behavior with a list of hostids.
 *
 * -O | --option=setting:value
 *
 *	Override a DB-provided value from the settings table in the DB.
 *
 * -C | -conf=FILE
 *
 *	Specify the location of the Spine configuration file.
 *
 * -R | --readonly
 *
 *	This processing is readonly with respect to the database: it's
 *	meant only for developer testing.
 *
 * -S | --stdout
 *
 *	All logging goes to the standard output
 *
 * -V | --verbosity=V
 *
 * Set the debug logging verbosity to <V>. Can be 1..5 or
 *	NONE/LOW/MEDIUM/HIGH/DEBUG (case insensitive).
 *
 * The First/Last device IDs are all relative to the "hosts" table in the
 * Cacti database, and this mechanism allows us to split up the polling
 * duties across multiple "spine" instances: each one gets a subset of
 * the polling range.
 *
 * For compatibility with poller.php, we also accept the first and last
 * device IDs as standalone parameters on the command line.
*/

#include "common.h"
#include "spine.h"
#include <limits.h>
#include "cli_internal.h"

static char *getarg(char *opt, char ***pargv);
static void display_help(int only_version);

typedef enum {
	CLI_FIRST,
	CLI_LAST,
	CLI_POLLER,
	CLI_THREADS,
	CLI_PINGONLY,
	CLI_MODE,
	CLI_HOSTLIST,
	CLI_MIBS,
	CLI_HELP,
	CLI_VERSION,
	CLI_OPTION,
	CLI_READONLY,
	CLI_CONF,
	CLI_STDOUT,
	CLI_LOG,
	CLI_VERBOSITY,
	CLI_UNKNOWN
} cli_option_t;

typedef struct {
	const char *name;
	cli_option_t option;
	bool ignore_case;
} cli_alias_t;

static cli_option_t lookup_cli_option(const char *arg) {
	static const cli_alias_t aliases[] = {
		{"-f", CLI_FIRST, TRUE},
		{"--first", CLI_FIRST, FALSE},
		{"-l", CLI_LAST, TRUE},
		{"--last", CLI_LAST, TRUE},
		{"-p", CLI_POLLER, FALSE},
		{"--poller", CLI_POLLER, TRUE},
		{"-t", CLI_THREADS, FALSE},
		{"--threads", CLI_THREADS, TRUE},
		{"-P", CLI_PINGONLY, FALSE},
		{"--pingonly", CLI_PINGONLY, TRUE},
		{"-N", CLI_MODE, FALSE},
		{"--mode", CLI_MODE, TRUE},
		{"-H", CLI_HOSTLIST, FALSE},
		{"--hostlist", CLI_HOSTLIST, TRUE},
		{"-M", CLI_MIBS, TRUE},
		{"--mibs", CLI_MIBS, FALSE},
		{"-h", CLI_HELP, TRUE},
		{"--help", CLI_HELP, FALSE},
		{"-v", CLI_VERSION, FALSE},
		{"--version", CLI_VERSION, FALSE},
		{"-O", CLI_OPTION, TRUE},
		{"--option", CLI_OPTION, TRUE},
		{"-R", CLI_READONLY, TRUE},
		{"--readonly", CLI_READONLY, FALSE},
		{"--read-only", CLI_READONLY, FALSE},
		{"-C", CLI_CONF, TRUE},
		{"--conf", CLI_CONF, FALSE},
		{"-S", CLI_STDOUT, TRUE},
		{"--stdout", CLI_STDOUT, FALSE},
		{"-D", CLI_LOG, TRUE},
		{"--log", CLI_LOG, FALSE},
		{"-V", CLI_VERBOSITY, FALSE},
		{"--verbosity", CLI_VERBOSITY, FALSE},
	};
	for (size_t index = 0; index < sizeof(aliases) / sizeof(aliases[0]); index++) {
		bool matches = aliases[index].ignore_case ? STRIMATCH(arg, aliases[index].name) : STRMATCH(arg, aliases[index].name);
		if (matches) return aliases[index].option;
	}
	return CLI_UNKNOWN;
}

static void parse_polling_mode(const char *requested_mode) {
	if (STRIMATCH(requested_mode, "online")) {
		set.poller.mode = REMOTE_ONLINE;
	} else if (STRIMATCH(requested_mode, "offline")) {
		set.poller.mode = REMOTE_OFFLINE;
	} else if (STRIMATCH(requested_mode, "recovery")) {
		set.poller.mode = REMOTE_RECOVERY;
	} else {
		die("ERROR: invalid polling mode '%s' specified", requested_mode);
	}
}

static void parse_host_list(const char *input) {
	if (strnlen(input, sizeof(set.hosts.host_id_list)) == sizeof(set.hosts.host_id_list)) {
		die("ERROR: invalid or oversized host list");
	}
	size_t used = 0;
	const char *cursor = input;
	for (;;) {
		while (isspace((unsigned char) *cursor)) cursor++;
		if (*cursor < '0' || *cursor > '9') die("ERROR: invalid or oversized host list");
		errno = 0;
		char *end;
		unsigned long id = strtoul(cursor, &end, 10);
		if (errno == ERANGE || id > INT_MAX) die("ERROR: invalid or oversized host list");
		while (isspace((unsigned char) *end)) end++;
		if (*end != '\0' && *end != ',') die("ERROR: invalid or oversized host list");
		/* SQL receives only converted integer values and owned separators. */
		used += (size_t) spine_snprintf(set.hosts.host_id_list + used,
			sizeof(set.hosts.host_id_list) - used, "%s%lu", used == 0 ? "" : ",", id);
		if (*end == '\0') return;
		cursor = end + 1;
	}
}

/* atoi() turned "-f abc" into device 0 and let "-t -1" size the connection
 * pools, so only a whole unsigned decimal number inside the range passes. */
static bool parse_cli_int(const char *text, long minimum, long maximum, int *value) {
	char *end;
	long parsed;

	if (text[0] < '0' || text[0] > '9') return FALSE;
	errno = 0;
	parsed = strtol(text, &end, 10);
	if (errno != 0 || *end != '\0' || parsed < minimum || parsed > maximum) return FALSE;
	*value = (int) parsed;
	return TRUE;
}

static void parse_cli_argument(const char *arg, char *opt, char ***argv, char **conf_file) {
	switch (lookup_cli_option(arg)) {
		case CLI_FIRST: {
			if (HOSTID_DEFINED(set.hosts.start_host_id)) {
				die("ERROR: %s can only be used once", arg);
			}

			opt = getarg(opt, argv);

			if (!parse_cli_int(opt, 0, INT_MAX, &set.hosts.start_host_id)) {
				die("ERROR: '%s=%s' is invalid first-host ID", arg, opt);
			}
			break;
		}
		case CLI_LAST: {
			if (HOSTID_DEFINED(set.hosts.end_host_id)) {
				die("ERROR: %s can only be used once", arg);
			}

			opt = getarg(opt, argv);

			if (!parse_cli_int(opt, 0, INT_MAX, &set.hosts.end_host_id)) {
				die("ERROR: '%s=%s' is invalid last-host ID", arg, opt);
			}
			break;
		}
		case CLI_POLLER: {
			set.poller.poller_id = atoi(getarg(opt, argv));
			break;
		}
		case CLI_THREADS: {
			opt = getarg(opt, argv);

			if (!parse_cli_int(opt, 1, INT_MAX, &set.poller.threads)) {
				die("ERROR: '%s=%s' is an invalid thread count, use 1 to %d", arg, opt, MAX_THREADS);
			}

			/* the database setting is capped the same way, and existing
			 * invocations above the cap have always run */
			if (set.poller.threads > MAX_THREADS) {
				fprintf(stderr, "WARNING: '%s=%s' exceeds the maximum thread count, using %d\n", arg, opt, MAX_THREADS);
				set.poller.threads = MAX_THREADS;
			}
			set.poller.threads_set = TRUE;
			break;
		}
		case CLI_PINGONLY: {
			set.availability.ping_only = TRUE;
			break;
		}
		case CLI_MODE: {
			parse_polling_mode(getarg(opt, argv));
			break;
		}
		case CLI_HOSTLIST: {
			parse_host_list(getarg(opt, argv));
			break;
		}
		case CLI_MIBS: {
			set.snmp.mibs = 1;
			break;
		}
		case CLI_HELP: {
			display_help(FALSE);

			exit(EXIT_SUCCESS);
		}
		case CLI_VERSION: {
			display_help(TRUE);

			exit(EXIT_SUCCESS);
		}
		case CLI_OPTION: {
			const char *setting = getarg(opt, argv);
			char *value = strchr(setting, ':');

			if (value != NULL && value != setting) {
				*value++ = '\0';
			} else {
				die("ERROR: -O requires setting:value");
			}

			set_option(setting, value);
			break;
		}
		case CLI_READONLY: {
			set.poller.SQL_readonly = TRUE;
			break;
		}
		case CLI_CONF: {
			char *replacement = strdup(getarg(opt, argv));
			if (replacement == NULL) die("ERROR: Fatal malloc error: spine.c conf_file!");
			SPINE_FREE(*conf_file);
			*conf_file = replacement;
			break;
		}
		case CLI_STDOUT: {
			set_option("log_destination", "STDOUT");
			break;
		}
		case CLI_LOG: {
			set_option("log_destination", getarg(opt, argv));
			break;
		}
		case CLI_VERBOSITY: {
			set_option("log_verbosity", getarg(opt, argv));
			break;
		}
		default:
			if (!HOSTID_DEFINED(set.hosts.start_host_id) && all_digits(arg)) {
				if (!parse_cli_int(arg, 0, INT_MAX, &set.hosts.start_host_id)) {
					die("ERROR: '%s' is invalid first-host ID", arg);
				}
			}

			else if (!HOSTID_DEFINED(set.hosts.end_host_id) && all_digits(arg)) {
				if (!parse_cli_int(arg, 0, INT_MAX, &set.hosts.end_host_id)) {
					die("ERROR: '%s' is invalid last-host ID", arg);
				}
			}

			else {
				die("ERROR: %s is an unknown command-line parameter", arg);
			}
			break;
	}
}

void parse_command_line(char **argv, char **conf_file) {
	argv++;
	while (*argv) {
		const char *arg = *argv;
		char *opt = strchr(arg, '=');
		if (opt) *opt++ = '\0';
		parse_cli_argument(arg, opt, &argv, conf_file);
		argv++;
	}
}

/*! \fn static void display_help()
 *  \brief Display Spine usage information to the caller.
 *
 *	Display the help listing: the first line is created at runtime with
 *	the version information, and the rest is strictly static text which
 *	is dumped literally.
 *
 */
static void display_help(int only_version) {
	static const char *const *p;
	static const char *const helptext[] = {
		"Usage: spine [options] [[firstid lastid] || [-H/--hostlist='hostid1,hostid2,...,hostidn']]",
		"",
		"Options:",
		"  -h/--help          Show this brief help listing",
		"  -f/--first=X       Start polling with host id X",
		"  -l/--last=X        End polling with host id X",
		"  -H/--hostlist=X    Poll the list of host ids, separated by comma's",
		"  -p/--poller=X      Set the poller id to X",
		"  -t/--threads=X     Override the database threads setting.",
		"  -C/--conf=F        Read spine configuration from file F",
		"  -O/--option=S:V    Override DB settings 'set' with value 'V'",
		"  -M/--mibs          Refresh the device System Mib data",
		"  -N/--mode=online   For remote pollers, the operating mode.",
		"                     Options include: online, offline, recovery.",
		"                     The default is 'online'.",
		"  -R/--readonly      Spine will not write output to the DB",
		"  -S/--stdout        Logging is performed to standard output",
		"  -P/--pingonly      Ping device and update device status only",
		"  -V/--verbosity=V   Set logging verbosity to <V>",
		"",
		"Either both of --first/--last must be provided, a valid hostlist must be provided.",
		"In their absence, all hosts are processed.",
		"",
		"Without the --conf parameter, spine searches in order:",
		"  current directory, /etc/, /etc/cacti/, ../etc/ for spine.conf.",
		"",
		"Verbosity is one of NONE/LOW/MEDIUM/HIGH/DEBUG or 1..5",
		"",
		"Runtime options are read from the 'settings' table in the Cacti",
		"database, but they can be overridden with the --option=S:V",
		"parameter.",
		"",
		"Spine is distributed under the Terms of the GNU Lesser",
		"General Public License Version 2.1. (http://www.gnu.org/licenses/lgpl.txt)",
		"For more information, see http://www.cacti.net",

		0 /* ENDMARKER */
	};

	printf("SPINE %s  Copyright 2004-2026 by The Cacti Group\n", VERSION);

	if (only_version == FALSE) {
		printf("\n");
		for (p = helptext; *p; p++) {
			puts(*p); /* automatically adds a newline */
		}
	}
}

/*! \fn static char *getarg(char *opt, char ***pargv)
 *  \brief A function to parse calling parameters
 *
 *	This is a helper for the main arg-processing loop: we work with
 *	options which are either of the form "-X=FOO" or "-X FOO"; we
 *	want an easy way to handle either one.
 *
 *	The idea is that if the parameter has an = sign, we use the rest
 *	of that same argv[X] string, otherwise we have to get the *next*
 *	argv[X] string. But it's an error if an option-requiring param
 *	is at the end of the list with no argument to follow.
 *
 *	The option name could be of the form "-C" or "--conf", but we
 *	grab it from the existing argv[] so we can report it well.
 *
 * \return character pointer to the argument
 *
 */
static char *getarg(char *opt, char ***pargv) {
	const char *const optname = **pargv;

	/* option already set? */
	if (opt) return opt;

	/* advance to next argv[] and try that one */
	if ((opt = *++(*pargv)) != 0) return opt;

	die("ERROR: option %s requires a parameter", optname);
}

#ifdef SPINE_TEST_PROGRAM_ENTRY
#undef main
#endif
