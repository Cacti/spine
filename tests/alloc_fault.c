/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (C) 2026 The Cacti Group
 * Linked only into the integration-test executable, never into Spine. */
#include "common.h"
#include "spine.h"
extern void *__real_calloc(size_t, size_t);
static pthread_mutex_t FaultMutex = PTHREAD_MUTEX_INITIALIZER;
static int Failed;

void *__wrap_calloc(size_t count, size_t size) {
	const char *mode = getenv("SPINE_TEST_ALLOC_FAILURE");
	int fail = FALSE;
	if (mode && count > 0 &&
		((strstr(mode, "target") && size == sizeof(target_t)) ||
		 (strstr(mode, "snmp") && size == sizeof(snmp_oids_t)))) {
		pthread_mutex_lock(&FaultMutex);
		fail = !Failed || !strstr(mode, "once");
		Failed = TRUE;
		pthread_mutex_unlock(&FaultMutex);
	}
	if (fail) { errno = ENOMEM; return NULL; }
	return __real_calloc(count, size);
}
