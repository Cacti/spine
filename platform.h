#ifndef SPINE_PLATFORM_H
#define SPINE_PLATFORM_H

#include <time.h>

int spine_platform_init(void);
void spine_platform_cleanup(void);

int spine_platform_setenv(const char *name, const char *value, int overwrite);
int spine_platform_localtime(const time_t *when, struct tm *out);

void spine_platform_sleep_ms(unsigned int milliseconds);
void spine_platform_sleep_us(unsigned int microseconds);
void spine_platform_sleep_s(unsigned int seconds);

unsigned long spine_platform_process_id(void);
int spine_platform_stdout_is_terminal(void);
int spine_platform_stderr_is_terminal(void);

#endif
