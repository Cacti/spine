#ifndef SPINE_RUNTIME_CONTEXT_H
#define SPINE_RUNTIME_CONTEXT_H

#include "common.h"
#include "spine.h"

typedef struct RuntimeConfig RuntimeConfig;
typedef struct RuntimeState RuntimeState;
typedef struct Logger Logger;

typedef int (*LoggerWriteFn)(const char *format, ...);

const RuntimeConfig *runtime_config_current(void);
const RuntimeState *runtime_state_current(void);
const Logger *runtime_logger_current(void);
const config_t *runtime_config_set(const RuntimeConfig *config);
double runtime_state_start_time(const RuntimeState *state);
LoggerWriteFn runtime_logger_write_fn(const Logger *logger);

#endif
