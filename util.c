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
#include <limits.h>

int spine_snprintf(char *output, size_t capacity, const char *format, ...) {
	va_list args;
	int length;

	va_start(args, format);
	length = vsnprintf(output, capacity, format, args);
	va_end(args);
	if (length < 0 || (size_t) length >= capacity) {
		set.exit.exit_code = EXIT_FAILURE;
		die("ERROR: Formatted output exceeds its destination buffer");
	}
	return length;
}

int spine_count_to_int(unsigned long long count) {
	if (count > INT_MAX) {
		set.exit.exit_code = EXIT_FAILURE;
		die("ERROR: Result count exceeds supported integer range");
	}
	return (int)count;
}

void spine_sleep_usec(unsigned int microseconds) {
	struct timespec requested = {
		(time_t)(microseconds / 1000000), (long)(microseconds % 1000000) * 1000
	};
	while (nanosleep(&requested, &requested) != 0) {
		if (errno != EINTR) {
			set.exit.exit_code = EXIT_FAILURE;
			die("ERROR: Unable to wait for retry delay");
		}
	}
}

double spine_monotonic_time(void) {
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
		set.exit.exit_code = EXIT_FAILURE;
		die("ERROR: Unable to read monotonic clock");
	}
	return (double)now.tv_sec + (double)now.tv_nsec / 1000000000;
}

static int spine_wait_fd(int fd, double deadline, bool writable) {
	if (fd < 0 || fd >= FD_SETSIZE) {
		errno = EBADF;
		return -1;
	}
	if (!isfinite(deadline)) {
		errno = EINVAL;
		return -1;
	}
	for (;;) {
		double remaining = deadline - spine_monotonic_time();
		if (remaining <= 0) return 0;
		if (remaining > INT_MAX) {
			errno = EINVAL;
			return -1;
		}
		struct timeval timeout;
		timeout.tv_sec = (time_t)remaining;
		timeout.tv_usec = (suseconds_t)((remaining - (double)timeout.tv_sec) * 1000000);
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(fd, &fds);
		int status = select(fd + 1, writable ? NULL : &fds, writable ? &fds : NULL, NULL, &timeout);
		if (status < 0 && errno == EINTR) continue;
		return status;
	}
}

int spine_wait_readable(int fd, double deadline) {
	return spine_wait_fd(fd, deadline, FALSE);
}

int spine_wait_writable(int fd, double deadline) {
	return spine_wait_fd(fd, deadline, TRUE);
}


int spine_permits_init(spine_permits_t *permits, int count) {
	if (count < 0) return EINVAL;
	int status = pthread_mutex_init(&permits->mutex, NULL);
	if (status == 0) permits->available = count;
	return status;
}

int spine_permits_destroy(spine_permits_t *permits) {
	return pthread_mutex_destroy(&permits->mutex);
}

static void spine_permits_lock(spine_permits_t *permits) {
	if (pthread_mutex_lock(&permits->mutex) != 0) {
		set.exit.exit_code = EXIT_FAILURE;
		die("ERROR: Unable to lock process permits");
	}
}

static void spine_permits_unlock(spine_permits_t *permits) {
	if (pthread_mutex_unlock(&permits->mutex) != 0) {
		set.exit.exit_code = EXIT_FAILURE;
		die("ERROR: Unable to unlock process permits");
	}
}

int spine_permits_try_acquire(spine_permits_t *permits) {
	spine_permits_lock(permits);
	int status = EAGAIN;
	if (permits->available > 0) {
		permits->available--;
		status = 0;
	}
	spine_permits_unlock(permits);
	return status;
}

int spine_permits_release(spine_permits_t *permits) {
	spine_permits_lock(permits);
	int status = EOVERFLOW;
	if (permits->available < INT_MAX) {
		permits->available++;
		status = 0;
	}
	spine_permits_unlock(permits);
	return status;
}

int spine_permits_available(spine_permits_t *permits) {
	spine_permits_lock(permits);
	int available = permits->available;
	spine_permits_unlock(permits);
	return available;
}

/* Raise, never lower, the platform default: glibc already gives 8 MiB, and a
 * smaller stack there would only add risk in code nobody has measured. */
int spine_thread_attr_init(pthread_attr_t *attributes) {
	size_t current = 0;
	size_t wanted = SPINE_THREAD_STACK_SIZE;
	int status;

#ifdef PTHREAD_STACK_MIN
	if (wanted < (size_t) PTHREAD_STACK_MIN) wanted = (size_t) PTHREAD_STACK_MIN;
#endif

	status = pthread_attr_init(attributes);
	if (status != 0) {
		return status;
	}

	if (pthread_attr_getstacksize(attributes, &current) == 0 && current >= wanted) {
		return 0;
	}

	status = pthread_attr_setstacksize(attributes, wanted);
	if (status != 0) {
		pthread_attr_destroy(attributes);
	}

	return status;
}

void spine_clear_sensitive(void *buffer, size_t length) {
	volatile unsigned char *bytes = buffer;
	while (length > 0) {
		*bytes++ = 0;
		length--;
	}
}

/*! \fn int is_debug_device(int device_id)
 *  \brief Determine if a device is a debug device
 *
 */
int is_debug_device(int device_id) {
	extern int *debug_devices;
	int i = 0;

	/* main() releases the list during shutdown; later logging must not read it. */
	if (debug_devices == NULL) return FALSE;

	while (i < MAX_DEBUG_DEVICES) {
		if (debug_devices[i] == '\0') break;
		if (debug_devices[i] == device_id) {
			return TRUE;
		}

		i++;
	}

	return FALSE;
}

void parse_debug_devices(char *device_list, int *devices, size_t capacity) {
	if (capacity == 0) return;
	devices[0] = 0;
	char *saveptr = NULL;
	const char *token = strtok_r(device_list, ",", &saveptr);
	for (size_t i = 0; token != NULL && i < capacity - 1; i++, token = strtok_r(NULL, ",", &saveptr)) {
		devices[i] = atoi(token);
		devices[i + 1] = 0;
	}
}

/*! \fn int file_exists(const char *filename)
 *  \brief checks for the existence of a file.
 *  \param *filename the name of the file to check for.
 *
 *  \return TRUE if found FALSE if not.
 *
 */
int file_exists(const char *filename) {
	struct stat file_stat;

	if (stat(filename, &file_stat)) {
		return FALSE;
	} else {
		return TRUE;
	}
}

/*! \fn char *strip_alpha(char *string)
 *  \brief remove trailing alpha characters from a string.
 *  \param string the string to strip characters from
 *
 *  \return a pointer to the modified string
 *
 */
char *strip_alpha(char *string) {
	size_t end = strlen(string);
	while (end > 0 && !isdigit((unsigned char) string[end - 1])) string[--end] = '\0';
	size_t start = 0;
	while (start < end && !isdigit((unsigned char) string[start]) && string[start] != '-') start++;
	return string + start;
}

/*! \fn char *add_slashes(const char *string)
 *  \brief add escaping to back slashes on for Windows type commands.
 *  \param string the string to replace slashes
 *
 *  \return a pointer to the modified string. Variable must be freed by parent.
 *
 */
char *add_slashes(const char *string) {
	size_t length = strlen(string);
	if (length > (SIZE_MAX - 1) / 2) {
		set.exit.exit_code = EXIT_FAILURE;
		die("ERROR: Escaped command exceeds addressable memory");
	}
	char *result = malloc(length * 2 + 1);
	if (result == NULL) die("ERROR: Fatal malloc error: util.c add_slashes!");
	size_t used = 0;
	for (size_t i = 0; i < length; i++) {
		if (string[i] == '\\') result[used++] = '\\';
		result[used++] = string[i];
	}
	result[used] = '\0';
	return result;
}

/*! \fn char *strncopy(char *dst, const char *src, size_t obuf)
 *  \brief copies source to destination add a NUL terminator
 *
 *	Copy from source to destination, insuring a NUL termination.
 *	The size of the buffer *includes* the terminating NUL. Note
 *	that strncpy() does NOT NUL terminate if the source is the
 *	size of the destination (yuck).
 *
 *	NOTE: it's very common to call this as:
 *
 *	  strncopy(buf, src, sizeof buf)
 *
 *	so we provide an STRNCOPY() macro which adds the size.
 *
 *  \return pointer to destination string
 *
*/
char *strncopy(char *dst, const char *src, size_t obuf) {
	assert(dst != NULL);
	assert(src != NULL);

	size_t len;

	if (obuf == 0) return dst;
	/* Bound the scan by the usable capacity; src may be large or unterminated. */
	len = strnlen(src, obuf - 1);
	if (len) {
		memcpy(dst, src, len);
	}

	dst[len] = '\0';
	return dst;
}

/*! \fn double get_time_as_double()
 *  \brief fetches system time as a double-precision value
 *
 *  \return system time (at microsecond resolution) as a double
 */
double get_time_as_double(void) {
	struct timeval now;

	gettimeofday(&now, NULL);

	return (double) now.tv_sec + (double) now.tv_usec / 1000000;
}

/*! \fn trim()
 *  \brief removes leading and trailing blanks, tabs, line feeds and
 *         carriage returns from a string.
 *
 *  \return the trimmed string.
 */
char *trim(char *str) {
	return ltrim(rtrim(str));
}

/*! \fn rtrim()
 *  \brief removes trailing blanks, tabs, line feeds, carriage returns
 *         single and double quotes and back-slashed from a string.
 *
 *  \return the trimmed string.
 */
char *rtrim(char *str) {
	char *end;
	const char *trim_chars = " \"\'\\\t\n\r";

	if (!str) return NULL;

	end = str + strlen(str);

	while (end > str) {
		--end;
		if (!strchr(trim_chars, *end)) return str;

		*end = 0;
	}

	return str;
}

/*! \fn ltrim()
 *  \brief removes leading blanks, tabs, line feeds, carriage returns
 *         single and double quotes and back-slashed from a string.
 *
 *  \return the trimmed string.
 */
char *ltrim(char *str) {
	const char *trim_chars = " \"\'\\\t\n\r";

	if (!str) return NULL;

	while (*str) {
		if (!strchr(trim_chars, *str)) return str;

		++str;
	}

	return str;
}

/*! \fn reverse()
 *  \brief reverses a string in place.
 *
 *  \return the reversed string.
 */
char *reverse(char *str) {
	size_t start = 0;
	size_t end = strlen(str);
	while (start < end) {
		end--;
		if (start >= end) break;
		char byte = str[start];
		str[start++] = str[end];
		str[end] = byte;
	}
	return str;
}

/*! \fn strpos()
 *  \brief looks for the position of needle in haystack
 *
 *  \return the position of -1 if not found
 */
int strpos(const char *haystack, const char *needle) {
	const char *p = strstr(haystack, needle);

	if (p) {
		return p - haystack <= INT_MAX ? (int) (p - haystack) : -1;
	}

	return -1;
}

/*! \fn char_count()
 *  \brief counts occurrences of char in string.
 *
 *  \return number of occurrences.
 */
int char_count(const char *str, int chr) {
	const unsigned char *my_str = (const unsigned char *) str;
	const unsigned char my_chr = (unsigned char) chr;
	int count = 0;

	if (!my_chr) return 1;

	while (*my_str) {
		if (*my_str++ == my_chr) {
			count++;
		}
	}
	return count;
}

/*! \fn int spine_appendf(char **cursor, size_t *remaining, const char *fmt, ...)
 *  \brief append to a bounded buffer without walking off the end
 *
 *  See util.h for why the `p += snprintf(...)` idiom this replaces is unsafe.
 *
 *  \return TRUE when the whole string was appended, FALSE otherwise
 */
int spine_appendf(char **cursor, size_t *remaining, const char *fmt, ...) {
	va_list args;
	int written;

	if (cursor == NULL || *cursor == NULL || remaining == NULL || *remaining == 0) {
		return FALSE;
	}

	va_start(args, fmt);
	written = vsnprintf(*cursor, *remaining, fmt, args);
	va_end(args);

	if (written < 0) {
		/* the buffer is untouched on an encoding error, but vsnprintf may have
		   written a partial result, so re-terminate where the cursor stands */
		**cursor = '\0';
		return FALSE;
	}

	if ((size_t) written >= *remaining) {
		/* Truncated. Leave the cursor on the terminator vsnprintf wrote, so
		   the buffer stays a valid string and every later append fails here
		   rather than running past the end. */
		*cursor += *remaining - 1;
		*remaining = 1;
		return FALSE;
	}

	*cursor    += written;
	*remaining -= (size_t) written;

	return TRUE;
}
