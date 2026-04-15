#ifndef SPINE_PLATFORM_H
#define SPINE_PLATFORM_H

#include <time.h>

int spine_platform_init(void);
void spine_platform_cleanup(void);

/* Internal one-time hooks implemented by the active platform backend. */
int spine_platform_init_once(void);
void spine_platform_cleanup_once(void);

int spine_platform_setenv(const char *name, const char *value, int overwrite);
int spine_platform_localtime(const time_t *when, struct tm *out);

void spine_platform_sleep_ms(unsigned int milliseconds);
void spine_platform_sleep_us(unsigned int microseconds);
void spine_platform_sleep_s(unsigned int seconds);

unsigned long spine_platform_process_id(void);
int spine_platform_stdout_is_terminal(void);
int spine_platform_stderr_is_terminal(void);

/* Best-effort thread naming for debuggers, ps, and perf. Platforms that lack
 * a thread-name facility return silently. Names longer than the platform's
 * limit (Linux: 15 bytes + NUL, macOS: 63) are truncated by the OS. */
void spine_platform_set_thread_name(const char *name);

#endif
