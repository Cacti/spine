/*
 * Copyright (C) 2004-2026 The Cacti Group
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 */
#include "common.h"
#include "spine.h"

extern int putsetting(MYSQL *, int, const char *, const char *);

static void assert_saved_setting(MYSQL *mysql, const char *name, const char *expected) {
	char query[BUFSIZE];
	spine_snprintf(query, sizeof(query), "SELECT value FROM settings WHERE name='%s'", name);
	MYSQL_RES *result = db_query(mysql, LOCAL, query);
	assert(result != NULL && mysql_num_rows(result) == 1);
	MYSQL_ROW row = mysql_fetch_row(result);
	assert(row != NULL && row[0] != NULL && strcmp(row[0], expected) == 0);
	db_free_result(result);
}

void test_settings_write_contracts(MYSQL *mysql) {
	config_t previous = set;
	set.database.onupdate = 0; /* MariaDB's supported INSERT ... VALUES upsert dialect. */
	set.poller.SQL_readonly = FALSE;
	char name[100];
	char trigger[100];
	spine_snprintf(name, sizeof(name), "spine_settings_fault_%ld", (long)getpid());
	spine_snprintf(trigger, sizeof(trigger), "spine_settings_reject_%ld", (long)getpid());
	char query[LRG_BUFSIZE];
	/* This owned key is ASCII letters/digits/underscores; reader escaping is
	 * a separate contract from the writer's result being verified here. */
	spine_snprintf(query, sizeof(query), "DELETE FROM settings WHERE name='%s'", name);
	assert(db_insert(mysql, LOCAL, query));
	assert(putsetting(mysql, LOCAL, name, "first value") == TRUE);
	assert_saved_setting(mysql, name, "first value");
	assert(putsetting(mysql, LOCAL, name, "multibyte café 🌵") == TRUE);
	assert_saved_setting(mysql, name, "multibyte café 🌵");
	assert(putsetting(mysql, LOCAL, name, "multibyte café 🌵") == TRUE);
	assert_saved_setting(mysql, name, "multibyte café 🌵");
	spine_snprintf(query, sizeof(query), "CREATE TRIGGER %s BEFORE INSERT ON settings FOR EACH ROW BEGIN IF NEW.name='%s' THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='owned settings failure'; END IF; END", trigger, name);
	assert(db_insert(mysql, LOCAL, query));
	assert(putsetting(mysql, LOCAL, name, "failed replacement") == FALSE);
	assert_saved_setting(mysql, name, "multibyte café 🌵");
	spine_snprintf(query, sizeof(query), "DROP TRIGGER %s", trigger);
	assert(db_insert(mysql, LOCAL, query));
	assert(putsetting(mysql, LOCAL, name, "retried replacement") == TRUE);
	assert_saved_setting(mysql, name, "retried replacement");
	spine_snprintf(query, sizeof(query), "DELETE FROM settings WHERE name='%s'", name);
	assert(db_insert(mysql, LOCAL, query));
	set = previous;
	puts("production settings write outcome regressions passed");
}
