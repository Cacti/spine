#include "common.h"
#include "spine.h"
#include "log_formatter.h"

size_t spine_log_formatter_prefix(char *out, size_t out_len, int poller_id) {
	return snprintf(out, out_len, "SPINE: Poller[%i] PID[%lu] PT[%lu] ",
		poller_id, spine_platform_process_id(), (unsigned long int)pthread_self());
}

size_t spine_log_formatter_line(char *out, size_t out_len, const char *prefix, const char *message) {
	return snprintf(out, out_len, "%s%s", prefix ? prefix : "", message ? message : "");
}
