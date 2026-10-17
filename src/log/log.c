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

#include "internal/common.h"
#include "app/spine.h"

/* Preserve printable device output while keeping each log record on one line.
 * Also remove terminal controls and Unicode line/paragraph separators. */


/*! \fn void die(const char *format, ...)
 *  \brief a method to end Spine while returning the fatal error to stderr
 *
 *	Given a printf-style argument list, format it to the standard
 *	error, append a newline, then exit Spine.
 *
 */
void die(const char *format, ...) {
	va_list args;
	char logmessage[BUFSIZE];
	char flogmessage[DBL_BUFSIZE];
	int old_errno = errno;

	va_start(args, format);
	vsnprintf(logmessage, sizeof(logmessage), format, args);
	va_end(args);

	if (set.logging.log_perror) {
		char perr[BUFSIZE];
		snprintf(perr, BUFSIZE, " [%d, %s]", old_errno, strerror(old_errno));
		size_t used = strlen(logmessage);
		snprintf(logmessage + used, sizeof(logmessage) - used, "%s", perr);
	}
	spine_sanitize_log_message(logmessage);

	if (set.logging.logfile_processed) {
		if (set.poller.parent_fork == SPINE_PARENT) {
			snprintf(flogmessage, DBL_BUFSIZE, "%s (Spine parent)", logmessage);
		} else {
			snprintf(flogmessage, DBL_BUFSIZE, "%s (Spine thread)", logmessage);
		}
	} else {
		snprintf(flogmessage, DBL_BUFSIZE, "%s (Spine init)", logmessage);
	}

	fprintf(stderr, "%s\n", flogmessage);

	if ((set.poller.parent_fork == SPINE_PARENT) && (set.php.php_initialized)) {
		php_close(PHP_INIT);
	}

	exit(set.exit.exit_code == EXIT_SUCCESS ? EXIT_FAILURE : set.exit.exit_code);
}

/* The log timestamp format depends only on two settings read once in
 * read_config_options(), so it is built there, while spine is still single
 * threaded, and only read afterwards. Rebuilding it per log line cost a
 * malloc/free pair on every message. */
static char log_date_format[GD_FMT_SIZE] = "%Y/%b/%d %H:%M:%S - ";

/*! \fn void set_date_format(void)
 *  \brief build the cached log timestamp format from the current settings
 *
 *  Not safe to call after the poller threads have started.
 */
void set_date_format(void) {
	static const char separators[] = {'-', '/', '.'};
	static const char *const formats[][3] = {
		{"%m", "%d", "%Y"}, {"%b", "%d", "%Y"},
		{"%d", "%m", "%Y"}, {"%d", "%b", "%Y"},
		{"%Y", "%m", "%d"}, {"%Y", "%b", "%d"}};
	if (set.logging.log_datetime_separator < GDC_MIN || set.logging.log_datetime_separator > GDC_MAX) {
		set.logging.log_datetime_separator = GDC_DEFAULT;
	}
	if (set.logging.log_datetime_format < GD_MIN || set.logging.log_datetime_format > GD_MAX) {
		set.logging.log_datetime_format = GD_DEFAULT;
	}
	char separator = separators[set.logging.log_datetime_separator];
	const char *const *parts = formats[set.logging.log_datetime_format];
	spine_snprintf(log_date_format, sizeof(log_date_format), "%s%c%s%c%s %%H:%%M:%%S - ",
		parts[0], separator, parts[1], separator, parts[2]);
}

char *get_date_format(void) {
	return log_date_format;
}

/*! \fn void spine_log(const char *format, ...)
 *  \brief output's log information to the desired cacti logfile.
 *  \param *logmessage a pointer to the pre-formatted log message.
 *
 */
bool spine_should_log_device(int host_id, int verbosity) {
	return is_debug_device(host_id) || set.logging.log_level >= verbosity;
}

static FILE *log_error_stream(void) {
#ifdef DISABLE_STDERR
	return stdout;
#else
	return stderr;
#endif
}

static bool log_stream_available(const FILE *stream) {
	return (stream == stdout && !set.console.stdout_notty) || (stream == stderr && !set.console.stderr_notty);
}

static void log_format_error(const char *message) {
	FILE *stream = log_error_stream();
	if (log_stream_available(stream)) fprintf(stream, "%s\n", message);
}

static bool log_format_message(char *output, size_t capacity, const char *message) {
	char prefix[SMALL_BUFSIZE];
	snprintf(prefix, sizeof(prefix), "SPINE: Poller[%i] PID[%i] PT[%lu] ", set.poller.poller_id, getpid(), (unsigned long int) pthread_self());
	time_t now = time(NULL);
	struct tm local;
	const char *date_format = get_date_format();
	size_t date_length = 0;
	if (localtime_r(&now, &local) != NULL) date_length = strftime(output, 50, date_format, &local);
	if (date_length == 0) {
		output[0] = '\0';
		log_format_error("ERROR: Could not get string from strftime()");
	}
	int prefix_length = spine_count_to_int(strlen(prefix));
	int message_length = spine_count_to_int(strlen(message));
	int available = spine_count_to_int(capacity) - spine_count_to_int(date_length) - 2;
	if (prefix_length > available) prefix_length = available;
	if (message_length > available - prefix_length) message_length = available - prefix_length;
	snprintf(output + date_length, capacity - date_length, "%.*s%.*s", prefix_length, prefix, message_length, message);
	return date_length != 0;
}

static void log_to_syslog(const char *message) {
	if (!IS_LOGGING_TO_SYSLOG()) return;
	openlog("Cacti", LOG_NDELAY | LOG_PID, LOG_SYSLOG);
	if ((strstr(message, "ERROR") || strstr(message, "FATAL")) && set.logging.log_perror) syslog(LOG_CRIT, "%s\n", message);
	if (strstr(message, "WARNING") && set.logging.log_pwarn) syslog(LOG_WARNING, "%s\n", message);
	if (strstr(message, "STATS") && set.logging.log_pstats) syslog(LOG_NOTICE, "%s\n", message);
	closelog();
}

static bool log_to_file(const char *message) {
	if (!IS_LOGGING_TO_FILE() || set.logging.log_level == POLLER_VERBOSITY_NONE || !set.logging.path_logfile[0] || !set.logging.logfile_processed) return TRUE;
	/* Serialize complete records and the once-only diagnostic. Append mode
	 * creates missing files without a stat/open race that can truncate them. */
	static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
	static bool reported_error = FALSE;
	if (pthread_mutex_lock(&mutex) != 0) return FALSE;
	/* O_APPEND selects the end atomically and one write() keeps another
	 * process sharing the log from splicing into a record. Reopening per
	 * message preserves log rotation. */
	int oldstate;
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);
	int fd = open(set.logging.path_logfile, O_WRONLY | O_CREAT | O_APPEND, 0640);
	bool success = FALSE;
	if (fd >= 0) {
		size_t length = strlen(message);
		ssize_t written = write(fd, message, length);
		success = written >= 0 && (size_t) written == length;
		if (close(fd) != 0) success = FALSE;
	}
	pthread_setcancelstate(oldstate, NULL);
	if (!success && !reported_error) {
		printf("ERROR: Spine Log File Could Not Be Opened/Created or Written\n");
		reported_error = TRUE;
	}
	if (pthread_mutex_unlock(&mutex) != 0) return FALSE;
	return success;
}

/* Three LOGSIZE records on the stack overran the 128 KiB musl default thread
 * stack.  Each thread takes its buffers from the heap on its first message
 * and keeps them until it exits; if that allocation fails the record is
 * still written, cut to BUFSIZE. */
typedef struct {
	char message[LOGSIZE];
	char formatted[LOGSIZE];
} log_buffers_t;

static pthread_key_t log_buffers_key;
static pthread_once_t log_buffers_once = PTHREAD_ONCE_INIT;
static bool log_buffers_keyed = FALSE;

static void log_buffers_create_key(void) {
	log_buffers_keyed = pthread_key_create(&log_buffers_key, free) == 0;
}

static log_buffers_t *log_buffers(void) {
	log_buffers_t *buffers;
	if (pthread_once(&log_buffers_once, log_buffers_create_key) != 0 || !log_buffers_keyed) return NULL;
	buffers = pthread_getspecific(log_buffers_key);
	if (buffers != NULL) return buffers;
	buffers = malloc(sizeof(*buffers));
	if (buffers != NULL && pthread_setspecific(log_buffers_key, buffers) != 0) {
		free(buffers);
		buffers = NULL;
	}
	return buffers;
}

int spine_log(const char *format, ...) {
	char fallback_message[BUFSIZE];
	char fallback_formatted[BUFSIZE];
	log_buffers_t *buffers = log_buffers();
	char *message = buffers != NULL ? buffers->message : fallback_message;
	char *formatted = buffers != NULL ? buffers->formatted : fallback_formatted;
	size_t capacity = buffers != NULL ? LOGSIZE : BUFSIZE;
	va_list args;
	va_start(args, format);
	vsnprintf(message, capacity - 1, format, args);
	va_end(args);
	spine_sanitize_log_message(message);
	if (IS_LOGGING_TO_STDOUT()) {
		return printf("Total[%3.4f] %s\n", get_time_as_double() - start_time, message) < 0 ? FALSE : TRUE;
	}
	bool date_valid = log_format_message(formatted, capacity, message);
	log_to_syslog(formatted);
	if (strchr(formatted, '\n') == NULL) {
		size_t used = strlen(formatted);
		snprintf(formatted + used, capacity - used, "\n");
	}
	bool success = log_to_file(formatted);
	if (set.logging.log_level >= POLLER_VERBOSITY_NONE) {
		FILE *stream = stdout;
		if (!date_valid || strstr(formatted, "ERROR") || strstr(formatted, "WARNING") || strstr(formatted, "FATAL")) stream = log_error_stream();
		if (log_stream_available(stream) && fprintf(stream, "%s", formatted) < 0) success = FALSE;
	}
	return success;
}
