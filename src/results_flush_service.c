#include "common.h"
#include "spine.h"
#include "host_polling_service.h"
#include "results_flush_service.h"

ResultCode results_flush_service_flush(MYSQL *mysql, int type, const char *query) {
	if (db_insert(mysql, type, query)) {
		return RESULT_CODE_OK;
	}
	return RESULT_CODE_ERROR;
}
