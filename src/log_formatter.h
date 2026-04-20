#ifndef SPINE_LOG_FORMATTER_H
#define SPINE_LOG_FORMATTER_H

#include "common.h"
#include "spine.h"

size_t spine_log_formatter_prefix(char *out, size_t out_len, int poller_id);
size_t spine_log_formatter_line(char *out, size_t out_len, const char *prefix, const char *message);

#endif
