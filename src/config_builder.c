#include "common.h"
#include "spine.h"
#include "config_builder.h"

void config_builder_build(const config_t *current, const ConfigRepositoryData *raw, RuntimeConfigDraft *draft) {
	memset(draft, 0, sizeof(*draft));
	draft->set_values = *current;

	if (raw->dbversion[0] != '\0') {
		snprintf(draft->set_values.dbversion, sizeof(draft->set_values.dbversion), "%s", raw->dbversion);
	}

	if (STRIMATCH(draft->set_values.dbversion, "mariadb")) {
		draft->set_values.dbonupdate = 0;
	} else if (strpos(draft->set_values.dbversion, "8.") == 0) {
		draft->set_values.dbonupdate = 1;
	} else {
		draft->set_values.dbonupdate = 0;
	}

	if (raw->cacti_version > 0) {
		draft->set_values.cacti_version = raw->cacti_version;
	}

	if (raw->log_verbosity > 0) {
		draft->set_values.log_level = raw->log_verbosity;
	}

	if (raw->path_webroot[0] != '\0') {
		snprintf(draft->set_values.path_php_server, sizeof(draft->set_values.path_php_server),
			"%s/script_server.php", raw->path_webroot);
	}

	if (raw->path_cactilog[0] != '\0') {
		snprintf(draft->set_values.path_logfile, sizeof(draft->set_values.path_logfile), "%s", raw->path_cactilog);
	} else if (raw->path_webroot[0] != '\0') {
		snprintf(draft->set_values.path_logfile, sizeof(draft->set_values.path_logfile),
			"%s/log/cacti.log", raw->path_webroot);
	}

	if (raw->path_php_binary[0] != '\0') {
		snprintf(draft->set_values.path_php, sizeof(draft->set_values.path_php), "%s", raw->path_php_binary);
	}

	if (raw->default_datechar >= GDC_MIN && raw->default_datechar <= GDC_MAX) {
		draft->set_values.log_datetime_separator = raw->default_datechar;
	}

	if (raw->log_destination > 0) {
		draft->set_values.log_destination = raw->log_destination;
	}

	if (raw->availability_method > 0) {
		draft->set_values.availability_method = raw->availability_method;
	}

	if (raw->ping_recovery_count > 0) {
		draft->set_values.ping_recovery_count = raw->ping_recovery_count;
	}

	if (raw->ping_failure_count > 0) {
		draft->set_values.ping_failure_count = raw->ping_failure_count;
	}

	if (raw->ping_method > 0) {
		draft->set_values.ping_method = raw->ping_method;
	}

	if (raw->ping_retries > 0) {
		draft->set_values.ping_retries = raw->ping_retries;
	}

	if (raw->ping_timeout > 0) {
		draft->set_values.ping_timeout = raw->ping_timeout;
	}
}
