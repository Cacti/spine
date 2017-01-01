/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2017 The Cacti Group                                 |
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
/*!
 *
 *	This module provides keyword-lookup support for various spine
 *	objects. The idea is that we can do a two-way translation: given
 *	a token, return a printable name for it, and to take a word from
 *	the user and return the numeric internal value.
 *
 *	The center of the module is the table of keywords which map in
 *	both directions word<-->value. Lookups are case insensitive, and
 *	both direction
 *
*/

#include "common.h"
#include "spine.h"

struct keyword {
	const char *word;
	int         value;
};

/*! Log Level Structure
 *
 *	Structure that helps map either an integer value to a text logging level or
 *	vice versa.
 *
 */
static const struct keyword log_level[] = {
	{ "NONE",   POLLER_VERBOSITY_NONE   },
	{ "LOW",    POLLER_VERBOSITY_LOW    },
	{ "MEDIUM", POLLER_VERBOSITY_MEDIUM },
	{ "HIGH",   POLLER_VERBOSITY_HIGH   },
	{ "DEBUG",  POLLER_VERBOSITY_DEBUG  },

	{ 0, 0 }	/* ENDMARKER */
};

/*! Log Destination Structure
 *
 *	Structure that helps map either an integer value to a text logging destination
 *  or vice versa.
 *
 */
static const struct keyword logdest[] = {
	{ "FILE",   LOGDEST_FILE   },
	{ "SYSLOG", LOGDEST_SYSLOG },
	{ "BOTH",   LOGDEST_BOTH   },
	{ "STDOUT", LOGDEST_STDOUT },

	{ 0, 0 }	/* ENDMARKER */
};

/*! Poller Action Structure
 *
 *	Structure that helps map either an integer value to a text poller action
 *  or vice versa.
 *
 */
static const struct keyword actions[] = {
	{ "SNMP",       POLLER_ACTION_SNMP               },
	{ "SCRIPT",     POLLER_ACTION_SCRIPT             },
	{ "PHPSCRIPT",	POLLER_ACTION_PHP_SCRIPT_SERVER  },
	{ "SNMP_CT",        POLLER_ACTION_SNMP_COUNT               },
	{ "SCRIPT_CT",      POLLER_ACTION_SCRIPT_COUNT             },
	{ "PHPSCRIPT_CT",	POLLER_ACTION_PHP_SCRIPT_SERVER_COUNT  },

	{ 0, 0 }	/* ENDMARKER */
};

/*! \fn find_keyword_by_word(const struct keyword *tbl, const char *word, int dflt)
 *  \brief takes a generic word and returns either TRUE or FALSE
 *  \param tbl the table that contains the translation from text to boolean
 *  \param word the word to compare against the table for the result
 *  \param dflt the default value to be returned if the string can not be found
 *
 *	Given a table of keywords and a user's word, look that word up in the
 *	table and return the value associted with it. If the word is not found,
 *	return the user-provide default value.
 *
 *	The default-value parameter can be used for either the actual default
 *	value of the parameter being searched for (say, LOGDEST_BOTH), or
 *	a didn't-find-it value (say, -1) which the caller can key off of.
 *
 *	NOTE: if the given word is all digits, it's parsed as a number and
 *	returned numerically.
 *
 *  \return TRUE, FALSE, or dflt depending on results of search
 *
 */
static int find_keyword_by_word(const struct keyword *tbl, const char *word, int dflt)
{
	assert(tbl  != 0);
	assert(word != 0);

	if (all_digits(word)) {
		return atoi(word);
	}

	for (; tbl->word; tbl++) {
		if (STRIMATCH(word, tbl->word)) {
			return tbl->value;
		}
	}

	return dflt;
}

/*! \fn static const char *find_keyword_by_value(const struct keyword *tbl, int value, const char *dflt)
 *  \brief searches a table for text string based upon a numeric input value
 *  \param tbl the table that contains the translation from text to boolean
 *  \param word the word to compare against the table for the result
 *  \param dflt the default value to be returned if the string can not be found
 *
 *	Given a keyword table and a numeric value, find the printable word
 *	associated with it. The *first* value found is returned (in case more
 *	than one word maps to the same value), and if it's not found, the
 *	user's default value is returned.
 *
 *	The dflt value is allowed to be NULL.
 *
 *  \return a string pointer to that matches the search criteria, or dflt
 *
 */
static const char *find_keyword_by_value(const struct keyword *tbl, int value, const char *dflt) {
	assert(tbl != 0);

	for (; tbl->word; tbl++ ) {
		if (tbl->value == value) {
			return tbl->word;
		}
	}

	return dflt;
}

const char *printable_log_level(int token) {
	return find_keyword_by_value(log_level, token, "-unknown-");
}

int parse_log_level(const char *word, int dflt) {
	return find_keyword_by_word(log_level, word, dflt);
}

const char *printable_logdest(int token) {
	return find_keyword_by_value(logdest, token, "-unknown-");
}

int parse_logdest(const char *word, int dflt) {
	return find_keyword_by_word(logdest, word, dflt);
}

const char *printable_action(int token) {
	return find_keyword_by_value(actions, token, "-unknown-");
}

int parse_action(const char *word, int dflt) {
	return find_keyword_by_word(actions, word, dflt);
}
