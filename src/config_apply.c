#include "common.h"
#include "spine.h"
#include "config_apply.h"

void config_apply_runtime(config_t *target, const RuntimeConfigDraft *draft) {
	*target = draft->set_values;
}
