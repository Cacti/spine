#include "common.h"
#include "spine.h"
#include "log_sink.h"

int spine_log_sink_stdout(const char *line) {
	if (line == NULL) {
		return FALSE;
	}
	puts(line);
	return TRUE;
}

int spine_log_sink_file(const char *path, const char *line) {
	FILE *log_file;

	if (path == NULL || line == NULL || *path == '\0') {
		return FALSE;
	}

	log_file = fopen(path, "a");
	if (log_file == NULL) {
		return FALSE;
	}

	fputs(line, log_file);
	fclose(log_file);
	return TRUE;
}

int spine_log_sink_syslog(const char *line) {
	if (line == NULL) {
		return FALSE;
	}

	openlog("Cacti", LOG_NDELAY | LOG_PID, LOG_SYSLOG);
	syslog(LOG_NOTICE, "%s", line);
	closelog();
	return TRUE;
}
