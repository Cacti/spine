#include "common.h"
#include "spine.h"
#include "snmp_result_parser.h"

int spine_snmp_result_is_numeric(const char *value) {
	if (value == NULL) {
		return FALSE;
	}
	return is_numeric((char *)value);
}

unsigned long long spine_snmp_result_parse_uptime(const char *value) {
	if (!spine_snmp_result_is_numeric(value)) {
		return 0ULL;
	}
	return strtoull(value, NULL, 10);
}
