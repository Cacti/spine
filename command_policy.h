#ifndef SPINE_COMMAND_POLICY_H
#define SPINE_COMMAND_POLICY_H

#include <stddef.h>

int spine_script_command_is_safe(const char *command, char *reason, size_t reason_size);

#endif
