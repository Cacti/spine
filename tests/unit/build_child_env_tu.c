/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Stand-alone copy of spine_build_child_env for the env_scrub unit test.
 | The in-tree definition in nft_popen.c lives behind common.h + spine.h
 | (mysql + net-snmp), which the test deliberately avoids. The
 | implementation MUST stay in sync with nft_popen.c:spine_build_child_env.
 | Any change here requires a matching change there and vice versa.
 +-------------------------------------------------------------------------+
*/

#include <stdlib.h>
#include <string.h>

extern char **environ;

static const char *const spine_dangerous_env_prefixes[] = {
	"LD_PRELOAD=",
	"LD_LIBRARY_PATH=",
	"LD_AUDIT=",
	"DYLD_INSERT_LIBRARIES=",
	"DYLD_LIBRARY_PATH=",
	"BASH_ENV=",
	"ENV=",
	NULL
};

static const char spine_default_path[] =
	"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
static const char spine_default_ifs[]  = "IFS= \t\n";

char **spine_build_child_env(void) {
	size_t n = 0;
	while (environ && environ[n]) n++;

	char **new_env = calloc(n + 3, sizeof(char *));
	if (!new_env) return NULL;

	int has_path = 0;
	int has_ifs  = 0;
	size_t w = 0;
	for (size_t r = 0; r < n; r++) {
		int skip = 0;
		for (size_t d = 0; spine_dangerous_env_prefixes[d]; d++) {
			size_t plen = strlen(spine_dangerous_env_prefixes[d]);
			if (strncmp(environ[r], spine_dangerous_env_prefixes[d], plen) == 0) {
				skip = 1;
				break;
			}
		}
		if (skip) continue;
		if (strncmp(environ[r], "PATH=", 5) == 0) has_path = 1;
		if (strncmp(environ[r], "IFS=",  4) == 0) has_ifs  = 1;
		new_env[w++] = environ[r];
	}
	if (!has_path) new_env[w++] = (char *)spine_default_path;
	if (!has_ifs)  new_env[w++] = (char *)spine_default_ifs;
	new_env[w] = NULL;
	return new_env;
}
