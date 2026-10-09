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

/*! \fn all_digits(const char *string)
 *  \brief verifies that a string is contains only numeric characters
 *  \param string the string to check
 *
 *  This function has no leeway: spaces and minus signs and decimal points
 *  are not digits, and an empty string is (by convention) not
 *  all-digits too.
 *
 *  \return TRUE if not alpha or special characters found, FALSE if non numeric found
 *
 */
int all_digits(const char *string) {
	/* empty string is not all digits */
	if (*string == '\0') return FALSE;

	while (isdigit((unsigned char) *string))
		string++;

	return *string == '\0';
}

/*! \fn is_ipaddress(const char *string)
 *  \brief verifies that a string is an ip address either v4 or v6
 *  \param string the string to check
 *
 *  This function simply checks to see if a string object is an ip address.
 *  If it is, it returns true else false.
 *
 *  \return TRUE if an ip address, or FALSE if non
 *
 */
int is_ipaddress(const char *string) {
	while (*string) {
		if ((isdigit((unsigned char) *string)) ||
			(*string == '.') ||
			(*string == ':')) {
			string++;

			continue;
		}

		return FALSE;
	}

	return TRUE;
}

/* Cacti's prepare_validate_result() trims quotes and line ends; Spine has
 * always trimmed blanks, tabs and backslashes as well. */
static const char result_padding[] = " \"'\\\t\n\r";

/* PHP is_numeric() grammar: no hex, no "0x", no inf or nan, which strtod()
 * would all accept. */
static bool decimal_syntax(const char *text, bool *integral) {
	const char *cursor = text;
	size_t digits = 0;

	*integral = TRUE;
	if (*cursor == '+' || *cursor == '-') cursor++;
	while (isdigit((unsigned char) *cursor)) {
		cursor++;
		digits++;
	}
	if (*cursor == '.') {
		*integral = FALSE;
		cursor++;
		while (isdigit((unsigned char) *cursor)) {
			cursor++;
			digits++;
		}
	}
	if (digits == 0) return FALSE;
	if (*cursor == 'e' || *cursor == 'E') {
		*integral = FALSE;
		cursor++;
		if (*cursor == '+' || *cursor == '-') cursor++;
		if (!isdigit((unsigned char) *cursor)) return FALSE;
		while (isdigit((unsigned char) *cursor)) cursor++;
	}
	return *cursor == '\0';
}

static bool parse_decimal(const char *text, classified_result_t *out) {
	bool integral;
	char *end;
	double real;

	if (!decimal_syntax(text, &integral)) return FALSE;

	if (integral) {
		errno = 0;
		if (text[0] == '-') {
			long long value = strtoll(text, &end, 10);
			if (errno == 0 && *end == '\0') {
				out->kind = RESULT_SIGNED;
				out->value.integer = (int64_t) value;
				return TRUE;
			}
		} else {
			unsigned long long value = strtoull(text, &end, 10);
			if (errno == 0 && *end == '\0') {
				out->kind = RESULT_COUNTER;
				out->value.counter = (uint64_t) value;
				return TRUE;
			}
		}
		/* Wider than 64 bits is still a number; the text is stored as is. */
	}

	errno = 0;
	real = strtod(text, &end);
	if (*end != '\0' || !isfinite(real) || (errno == ERANGE && fabs(real) == HUGE_VAL)) {
		return FALSE;
	}
	out->kind = RESULT_FLOAT;
	out->value.real = real;
	return TRUE;
}

/* Cacti's "name:value name:value" form: one ':' or '!' per field, fields
 * separated by single spaces. */
static bool multipart_syntax(const char *text) {
	size_t spaces = 0;
	size_t delimiters = 0;

	if (strchr(text, ':') == NULL && strchr(text, '!') == NULL) return FALSE;
	for (const char *cursor = text; *cursor != '\0'; cursor++) {
		if (*cursor == ':' || *cursor == '!') delimiters++;
		else if (*cursor == ' ') spaces++;
	}
	return spaces == 0 || spaces + 1 == delimiters;
}

static int hex_digit(int c) {
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

typedef enum {
	OCTETS_NONE,
	OCTETS_VALUE,
	OCTETS_OVERFLOW
} octets_t;

/* An OctetString such as a Hex-STRING Counter64: two-digit octets separated
 * by one space, '-' or ':', as Cacti's is_hexadecimal() requires. Like Cacti,
 * a lone octet such as "FF" counts; "42" never gets here as it is decimal. */
static octets_t parse_octets(const char *text, uint64_t *value) {
	const char *cursor = text;
	uint64_t number = 0;
	bool overflow = FALSE;

	for (;;) {
		int high = hex_digit((unsigned char) cursor[0]);
		int low = high < 0 ? -1 : hex_digit((unsigned char) cursor[1]);

		if (low < 0) return OCTETS_NONE;
		if (number > (UINT64_MAX >> 8)) overflow = TRUE;
		number = (number << 8) | (uint64_t) (high * 16 + low);
		cursor += 2;
		if (*cursor == '\0') break;
		if (*cursor != ' ' && *cursor != ':' && *cursor != '-') {
			return OCTETS_NONE;
		}
		cursor++;
	}

	if (overflow) return OCTETS_OVERFLOW;
	*value = number;
	return OCTETS_VALUE;
}

/*! \fn result_kind_t classify_result(const char *raw, classified_result_t *out)
 *  \brief decide what a script or SNMP agent returned and what to store
 *  \param raw the output as received; it is not modified
 *  \param out receives the kind, the parsed value and the text to store
 *
 *  The order is the one Spine has always used: a decimal number, Cacti's
 *  multipart output, a hex octet string, then a decimal number wrapped in
 *  text such as "4096 Bytes". Anything else, including output too long to
 *  store whole, is unknown and stored as U rather than as a guess.
 *
 *  \return the kind, also stored in out->kind
 */
result_kind_t classify_result(const char *raw, classified_result_t *out) {
	const char *start;
	const char *end;
	const char *core;
	size_t length;
	uint64_t octets;

	assert(out != NULL);
	out->kind = RESULT_UNKNOWN;
	out->value.counter = 0;
	SET_UNDEFINED(out->text);

	if (raw == NULL) return RESULT_UNKNOWN;

	start = raw + strspn(raw, result_padding);
	if (*start == '\0') return RESULT_UNKNOWN;
	/* start[0] is not padding, so this stops with at least one byte left */
	end = start + strlen(start);
	while (strchr(result_padding, end[-1]) != NULL) end--;

	length = (size_t) (end - start);
	if (length >= sizeof(out->text)) return RESULT_UNKNOWN;
	memcpy(out->text, start, length);
	out->text[length] = '\0';

	if (parse_decimal(out->text, out)) return out->kind;

	if (multipart_syntax(out->text)) {
		out->kind = RESULT_MULTIPART;
		return out->kind;
	}

	switch (parse_octets(out->text, &octets)) {
		case OCTETS_VALUE:
			out->kind = RESULT_HEX_COUNTER;
			out->value.counter = octets;
			snprintf(out->text, sizeof(out->text), "%llu", (unsigned long long) octets);
			return out->kind;
		case OCTETS_OVERFLOW:
			/* Stripping letters from a counter wider than 64 bits would leave
		 * its leading octet looking like a small decimal sample. */
			break;
		case OCTETS_NONE:
			/* strip_alpha() points into out->text, so move the number to the front. */
			core = strip_alpha(out->text);
			if (parse_decimal(core, out)) {
				memmove(out->text, core, strlen(core) + 1);
				return out->kind;
			}
			break;
	}

	out->kind = RESULT_UNKNOWN;
	out->value.counter = 0;
	SET_UNDEFINED(out->text);
	return RESULT_UNKNOWN;
}
