#include "command_policy.h"

#include <stdio.h>

static void command_policy_set_reason(char *reason, size_t reason_size, const char *message) {
	if (reason == NULL || reason_size == 0) {
		return;
	}

	snprintf(reason, reason_size, "%s", message);
}

int spine_script_command_is_safe(const char *command, char *reason, size_t reason_size) {
	const unsigned char *cursor;

	if (command == NULL || *command == '\0') {
		command_policy_set_reason(reason, reason_size, "empty command");
		return 0;
	}

	for (cursor = (const unsigned char *) command; *cursor != '\0'; cursor++) {
		switch (*cursor) {
		case ';':
		case '|':
		case '&':
		case '`':
		case '$':
		case '>':
		case '<':
		case '\n':
		case '\r':
			command_policy_set_reason(reason, reason_size, "contains blocked shell metacharacter");
			return 0;
		default:
			break;
		}
	}

	command_policy_set_reason(reason, reason_size, "");
	return 1;
}
