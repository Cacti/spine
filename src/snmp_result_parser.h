#ifndef SPINE_SNMP_RESULT_PARSER_H
#define SPINE_SNMP_RESULT_PARSER_H

#include "common.h"
#include "spine.h"

int spine_snmp_result_is_numeric(const char *value);
unsigned long long spine_snmp_result_parse_uptime(const char *value);

#endif
