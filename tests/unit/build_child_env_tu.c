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

static const char *const spine_dangerous_env_exact[] = {
	"BASH_ENV=",
	"ENV=",
	"PERL5OPT=",
	"PYTHONSTARTUP=",
	"PYTHONINSPECT=",
	"RUBYOPT=",
	"NODE_OPTIONS=",
	NULL
};

static int spine_env_is_dangerous(const char *entry) {
	if (strncmp(entry, "LD_", 3) == 0)   return 1;
	if (strncmp(entry, "DYLD_", 5) == 0) return 1;
	for (size_t d = 0; spine_dangerous_env_exact[d]; d++) {
		size_t plen = strlen(spine_dangerous_env_exact[d]);
		if (strncmp(entry, spine_dangerous_env_exact[d], plen) == 0) return 1;
	}
	return 0;
}

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
		if (spine_env_is_dangerous(environ[r])) continue;
		if (strncmp(environ[r], "PATH=", 5) == 0) has_path = 1;
		if (strncmp(environ[r], "IFS=",  4) == 0) has_ifs  = 1;
		new_env[w++] = environ[r];
	}
	if (!has_path) new_env[w++] = (char *)spine_default_path;
	if (!has_ifs)  new_env[w++] = (char *)spine_default_ifs;
	new_env[w] = NULL;
	return new_env;
}
