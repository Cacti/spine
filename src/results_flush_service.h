#ifndef SPINE_RESULTS_FLUSH_SERVICE_H
#define SPINE_RESULTS_FLUSH_SERVICE_H

#include "common.h"
#include "spine.h"
#include "host_polling_service.h"

ResultCode results_flush_service_flush(MYSQL *mysql, int type, const char *query);

#endif
