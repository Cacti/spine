#include "common.h"
#include "spine.h"
#include "runtime_context.h"

struct RuntimeConfig {
	const config_t *set;
};

struct RuntimeState {
	double start_time;
};

struct Logger {
	LoggerWriteFn write;
};

extern double start_time;

const RuntimeConfig *runtime_config_current(void) {
	static RuntimeConfig config = {0};
	config.set = &set;
	return &config;
}

const RuntimeState *runtime_state_current(void) {
	static RuntimeState state = {0};
	state.start_time = start_time;
	return &state;
}

const Logger *runtime_logger_current(void) {
	static Logger logger = {0};
	logger.write = spine_log;
	return &logger;
}

const config_t *runtime_config_set(const RuntimeConfig *config) {
	return config != NULL ? config->set : NULL;
}

double runtime_state_start_time(const RuntimeState *state) {
	return state != NULL ? state->start_time : 0.0;
}

LoggerWriteFn runtime_logger_write_fn(const Logger *logger) {
	return logger != NULL ? logger->write : NULL;
}
