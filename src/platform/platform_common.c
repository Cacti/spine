#include "platform.h"

static int spine_platform_initialized = 0;

int spine_platform_init(void) {
	if (spine_platform_initialized == 0) {
		if (spine_platform_init_once() != 0) {
			return -1;
		}
	}

	spine_platform_initialized++;

	return 0;
}

void spine_platform_cleanup(void) {
	if (spine_platform_initialized <= 0) {
		return;
	}

	spine_platform_initialized--;

	if (spine_platform_initialized == 0) {
		spine_platform_cleanup_once();
	}
}
