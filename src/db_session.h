#ifndef SPINE_DB_SESSION_H
#define SPINE_DB_SESSION_H

#include "common.h"
#include "spine.h"

void spine_db_session_apply_sql_mode(MYSQL *mysql, int type);

#endif
