/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Stand-alone copy of spine_redact_args for the redact_args unit test.    |
 | The in-tree definition in util.c lives behind common.h (mysql +         |
 | net-snmp), which the test deliberately avoids. This copy MUST stay in   |
 | sync with util.c:spine_redact_args. Any change here requires a matching |
 | change there and vice versa.                                            |
 +-------------------------------------------------------------------------+
*/

#include <stddef.h>
#include <string.h>

static const char *const cred_short_flags[] = {
	"c", "u", "a", "x", "p", NULL
};

static const char *const cred_long_flags[] = {
	"community", "password", "secret", NULL
};

static int is_space_byte(char c) {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

static void redact_putc(char *out, size_t outsz, size_t *pos, char c) {
	if (*pos + 1 < outsz) {
		out[*pos] = c;
		(*pos)++;
	}
	out[(*pos < outsz) ? *pos : (outsz ? outsz - 1 : 0)] = '\0';
}

static void redact_puts(char *out, size_t outsz, size_t *pos, const char *s) {
	while (*s) {
		redact_putc(out, outsz, pos, *s++);
	}
}

static void emit_mask(char *out, size_t outsz, size_t *pos) {
	redact_puts(out, outsz, pos, "***");
}

static int short_flag_is_cred(const char *flag, size_t flag_len) {
	int i;
	if (flag_len != 1) return 0;
	for (i = 0; cred_short_flags[i] != NULL; i++) {
		if (flag[0] == cred_short_flags[i][0]) return 1;
	}
	return 0;
}

static int long_flag_is_cred(const char *flag, size_t flag_len) {
	int i;
	size_t n;
	for (i = 0; cred_long_flags[i] != NULL; i++) {
		n = strlen(cred_long_flags[i]);
		if (flag_len == n && strncmp(flag, cred_long_flags[i], n) == 0) {
			return 1;
		}
	}
	return 0;
}

void spine_redact_args(const char *cmd, char *out, size_t outsz) {
	size_t pos = 0;
	const char *p;

	if (out == NULL || outsz == 0) return;
	out[0] = '\0';
	if (cmd == NULL) return;

	p = cmd;
	while (*p) {
		if (is_space_byte(*p)) {
			redact_putc(out, outsz, &pos, *p);
			p++;
			continue;
		}

		if (*p == '-') {
			int is_long = 0;
			const char *flag_start;
			const char *eq;
			const char *token_start = p;
			size_t flag_len;

			redact_putc(out, outsz, &pos, *p);
			p++;
			if (*p == '-') {
				is_long = 1;
				redact_putc(out, outsz, &pos, *p);
				p++;
			}

			flag_start = p;
			while (*p && !is_space_byte(*p) && *p != '=') {
				p++;
			}
			flag_len = (size_t)(p - flag_start);
			eq = (*p == '=') ? p : NULL;

			{
				const char *q;
				for (q = flag_start; q < flag_start + flag_len; q++) {
					redact_putc(out, outsz, &pos, *q);
				}
			}

			int redact = is_long ? long_flag_is_cred(flag_start, flag_len)
			                     : short_flag_is_cred(flag_start, flag_len);

			if (eq != NULL) {
				redact_putc(out, outsz, &pos, '=');
				p++;
				if (redact) {
					while (*p && !is_space_byte(*p)) p++;
					emit_mask(out, outsz, &pos);
				} else {
					while (*p && !is_space_byte(*p)) {
						redact_putc(out, outsz, &pos, *p);
						p++;
					}
				}
				continue;
			}

			if (!redact) {
				(void)token_start;
				continue;
			}

			while (*p && is_space_byte(*p)) {
				redact_putc(out, outsz, &pos, *p);
				p++;
			}
			if (*p == '\0') break;
			while (*p && !is_space_byte(*p)) p++;
			emit_mask(out, outsz, &pos);
			continue;
		}

		while (*p && !is_space_byte(*p)) {
			redact_putc(out, outsz, &pos, *p);
			p++;
		}
	}

	if (outsz > 0) {
		out[(pos < outsz) ? pos : outsz - 1] = '\0';
	}
}
