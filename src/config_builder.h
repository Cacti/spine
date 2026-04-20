#ifndef SPINE_CONFIG_BUILDER_H
#define SPINE_CONFIG_BUILDER_H

#include "common.h"
#include "spine.h"
#include "config_repository.h"

typedef struct RuntimeConfigDraft {
	config_t set_values;
} RuntimeConfigDraft;

void config_builder_build(const config_t *current, const ConfigRepositoryData *raw, RuntimeConfigDraft *draft);

#endif
