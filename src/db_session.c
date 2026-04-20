#include "common.h"
#include "spine.h"
#include "db_session.h"

void spine_db_session_apply_sql_mode(MYSQL *mysql, int type) {
	db_insert(mysql, type, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'NO_ZERO_DATE', ''))");
	db_insert(mysql, type, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'NO_ZERO_IN_DATE', ''))");
	db_insert(mysql, type, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'ONLY_FULL_GROUP_BY', ''))");
	db_insert(mysql, type, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'NO_AUTO_VALUE_ON_ZERO', ''))");
	db_insert(mysql, type, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'TRADITIONAL', ''))");
	db_insert(mysql, type, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'STRICT_ALL_TABLES', ''))");
	db_insert(mysql, type, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'STRICT_TRANS_TABLES', ''))");
}
