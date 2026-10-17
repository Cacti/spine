/*
 * SPDX-FileCopyrightText: 2004-2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Fork maintenance: Thomas Vincent.
 * Project contributor history: CONTRIBUTORS.md.
 */
#include "internal/common.h"
#include "app/spine.h"

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
	spine_snprintf(name, sizeof(name), "spine_settings_fault_%ld", (long) getpid());
	spine_snprintf(trigger, sizeof(trigger), "spine_settings_reject_%ld", (long) getpid());
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

/* Only the disposable fixture settings/poller tables are changed. Keep exact
 * copies because read_config_options() opens its own connection and therefore
 * cannot see a transaction on this test's connection. */
void test_config_option_boundaries(MYSQL *mysql) {
	config_t previous = set;
	char query[LRG_BUFSIZE];

	assert(db_insert(mysql, LOCAL, "CREATE TEMPORARY TABLE spine_saved_option_settings AS SELECT name,value FROM settings"));
	assert(db_insert(mysql, LOCAL, "CREATE TEMPORARY TABLE spine_saved_option_poller AS SELECT id,threads FROM poller WHERE id=1"));
	set.poller.poller_id = 1;
	set.poller.threads_set = FALSE;
	set.logging.log_destination = LOGDEST_STDOUT;
	set.logging.log_level = POLLER_VERBOSITY_NONE;
	set.hosts.host_id_list[0] = '\0';
	for (int high = 0; high <= 1; high++) {
		assert(db_insert(mysql, LOCAL, "DELETE FROM settings"));
		spine_snprintf(query, sizeof(query),
			"INSERT INTO settings(name,value) VALUES "
			"('log_verbosity','%d'),('log_destination','STDOUT'),"
			"('path_webroot','%s'),('path_cactilog','%s'),('path_php_binary','/fixture/php'),"
			"('default_datechar','%d'),('default_date_format','%d'),"
			"('availability_method','%d'),('ping_recovery_count','2'),('ping_failure_count','3'),"
			"('ping_method','%d'),('ping_retries','4'),('snmp_retries','2'),"
			"('poller_interval','%d'),('concurrent_processes','2'),('script_timeout','%d'),"
			"('selective_device_debug','42'),('spine_log_level','1'),('php_servers','%d'),"
			"('active_profiles','%d'),('total_snmp_ports','%d'),('max_get_size','%d'),"
			"('log_perror','on'),('log_pwarn','on'),('log_pstats','on'),"
			"('boost_redirect','on'),('boost_rrd_update_enable','on')",
			POLLER_VERBOSITY_DEBUG, high ? "/fixture/web" : "", high ? "/fixture/log" : "",
			high ? GDC_MAX + 1 : GDC_MIN - 1, high ? GD_MAX + 1 : GD_MIN - 1,
			AVAIL_NONE, PING_TCP, high ? 60 : 0, high ? 30 : 2,
			high ? MAX_PHP_SERVERS + 1 : 0, high ? 2 : -1, high ? 2 : -1,
			high ? 999 : 16);
		assert(db_insert(mysql, LOCAL, query));
		spine_snprintf(query, sizeof(query), "UPDATE poller SET threads=%d WHERE id=1", high ? MAX_THREADS + 1 : 3);
		assert(db_insert(mysql, LOCAL, query));
		read_config_options();
		assert(set.logging.log_level == POLLER_VERBOSITY_DEBUG);
		assert(set.logging.log_destination == LOGDEST_STDOUT);
		assert(strcmp(set.logging.path_logfile, high ? "/fixture/log" : "") == 0);
		assert(set.logging.log_datetime_separator == GDC_DEFAULT && set.logging.log_datetime_format == GD_DEFAULT);
		assert(strcmp(set.php.path_php, "/fixture/php") == 0);
		assert(set.availability.availability_method == AVAIL_NONE && set.availability.ping_method == PING_TCP);
		assert(set.availability.ping_recovery_count == 2 && set.availability.ping_failure_count == 3);
		assert(set.availability.ping_retries == 4 && set.snmp.snmp_retries == 2);
		assert(set.poller.threads == (high ? MAX_THREADS : 3));
		assert(set.poller.poller_interval == (high ? 60 : 0) && set.poller.num_parent_processes == 2);
		assert(set.php.script_timeout == (high ? 30 : 5));
		assert(set.php.php_servers == (high ? MAX_PHP_SERVERS : 1));
		assert(set.poller.active_profiles == (high ? 2 : 0) && set.snmp.total_snmp_ports == (high ? 2 : 0));
		assert(set.snmp.snmp_max_get_size == (high ? 128 : 16));
		assert(set.logging.log_perror && set.logging.log_pwarn && set.logging.log_pstats);
		assert(set.boost.boost_enabled && set.boost.boost_redirect);
		assert(strcmp(set.logging.selective_device_debug, "42") == 0 && set.logging.spine_log_level == 1);
		assert(!set.php.php_required); /* The fixture has no script-server items. */
		/* The preceding CLI override remains authoritative across reloads. */
		assert(set.availability.ping_timeout == 777);
	}
	assert(db_insert(mysql, LOCAL, "DELETE FROM settings"));
	assert(db_insert(mysql, LOCAL, "INSERT INTO settings(name,value) VALUES('log_destination','STDOUT')"));
	read_config_options();
	/* getsetting() represents absent rows as owned empty strings. Preserve
	 * that contract: numeric reads become zero before their existing clamps. */
	assert(set.php.script_timeout == 5 && set.php.php_servers == 1);
	assert(set.snmp.snmp_max_get_size == 0 && set.snmp.snmp_retries == 0);
	assert(set.poller.active_profiles == 0 && set.snmp.total_snmp_ports == 0);
	assert(set.poller.poller_interval == 0 && set.poller.num_parent_processes == 0);
	assert(!set.logging.log_perror && !set.logging.log_pwarn && !set.logging.log_pstats);
	assert(!set.boost.boost_enabled && !set.boost.boost_redirect);
	assert(set.availability.ping_timeout == 777);
	assert(db_insert(mysql, LOCAL, "DELETE FROM settings"));
	assert(db_insert(mysql, LOCAL, "INSERT INTO settings(name,value) SELECT name,value FROM spine_saved_option_settings"));
	assert(db_insert(mysql, LOCAL, "UPDATE poller p JOIN spine_saved_option_poller s ON p.id=s.id SET p.threads=s.threads"));
	assert(db_insert(mysql, LOCAL, "DROP TEMPORARY TABLE spine_saved_option_settings,spine_saved_option_poller"));
	set = previous;
	puts("production configuration option bounds and defaults passed");
}
