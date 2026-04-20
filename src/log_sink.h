#ifndef SPINE_LOG_SINK_H
#define SPINE_LOG_SINK_H

#include "common.h"
#include "spine.h"

int spine_log_sink_stdout(const char *line);
int spine_log_sink_file(const char *path, const char *line);
int spine_log_sink_syslog(const char *line);

#endif
