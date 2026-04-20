#include "common.h"
#include "spine.h"
#include "script_server_service.h"

char *script_server_service_exec(const char *command, int php_process) {
	return php_cmd(command, php_process);
}
