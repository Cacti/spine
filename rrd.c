/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004 Ian Berry                                            |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU General Public License             |
 | as published by the Free Software Foundation; either version 2          |
 | of the License, or (at your option) any later version.                  |
 |                                                                         |
 | This program is distributed in the hope that it will be useful,         |
 | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
 | GNU General Public License for more details.                            |
 +-------------------------------------------------------------------------+
 | cactid: a backend data gatherer for cacti                               |
 +-------------------------------------------------------------------------+
 | This poller would not have been possible without:                       |
 |   - Rivo Nurges (rrd support, mysql poller cache, misc functions)       |
 |   - RTG (core poller code, pthreads, snmp, autoconf examples)           |
 |   - Brady Alleman/Doug Warner (threading ideas, implimentation details) |
 +-------------------------------------------------------------------------+
 | - raXnet - http://www.raxnet.net/                                       |
 +-------------------------------------------------------------------------+
*/

#include "common.h"
#include "cactid.h"
#include "locks.h"
#include "sql.h"
#include "rrd.h"
#include "nft_popen.h"

extern MYSQL mysql;
extern char rrdtool_path[128];

FILE *rrdtool_stdin;
int rrdtool_fd;

void rrd_open() {
	char logmessage[255];
	if ((rrdtool_fd = nft_popen(rrdtool_path, "w")) == 0) {
		sprintf(logmessage,"ERROR: Failed to open the RRDTool pipe at: %s\n", rrdtool_path);
		cacti_log(logmessage,"e");
		exit(1);
	}
	rrdtool_stdin = fdopen(rrdtool_fd, "w");
}

void rrd_close() {
	fflush(rrdtool_stdin);
	if (rrdtool_stdin) {
		nft_pclose(rrdtool_fd);
	}else{
		cacti_log("ERROR: RRDTool pipe closed prematurely\n","e");
	}
}

void rrd_cmd(char *rrdcmd) {
	int argc = 0;
	int **argv;

	if (set.verbose >= HIGH) {
		printf("RRDCMD: %s\n", rrdcmd);
	}

	thread_mutex_lock(LOCK_RRDTOOL);
	fprintf(rrdtool_stdin, "%s\n", rrdcmd);
	thread_mutex_unlock(LOCK_RRDTOOL);

	free(rrdcmd);
}

char *create_rrd(int local_data_id, char *data_source_path, MYSQL *mysql) {
	MYSQL_RES *result;
	MYSQL_ROW row;

	int i;
	int consolidation_function_id, data_source_type_id, rrd_step;
	char query[BUFSIZE];
	char rra_string[BUFSIZE] = "";
	char ds_string[BUFSIZE] = "";
	char *rrdcmd = (char *) malloc(2048);
	char temp[64];
	char *cf[4] = {"AVERAGE", "MIN", "MAX", "LAST"};
	char *ds[4] = {"GAUGE", "COUNTER", "DERIVE", "ABSOLUTE"};

	/* get a list of RRAs in this RRD file */
	snprintf(query, BUFSIZE, "select data_template_data.rrd_step,rra.x_files_factor,rra.steps,rra.rows,rra_cf.consolidation_function_id,(rra.rows*rra.steps) as rra_order from data_template_data left join data_template_data_rra on data_template_data.id=data_template_data_rra.data_template_data_id left join rra on data_template_data_rra.rra_id=rra.id left join rra_cf on rra.id=rra_cf.rra_id where data_template_data.local_data_id=%i and (rra.steps is not null or rra.rows is not null) order by rra_cf.consolidation_function_id,rra_order", local_data_id);

	result = db_query(mysql, query);

	/* loop through each RRA */
	for (i=0; i<mysql_num_rows(result); i++) {
		row = mysql_fetch_row(result);

		consolidation_function_id = (atoi(row[4]) - 1);
		snprintf(temp, sizeof(temp), "RRA:%s:%s:%s:%s ", cf[consolidation_function_id], row[1], row[2], row[3]);

		strncat(rra_string, temp, BUFSIZE);

		rrd_step = atoi(row[0]);
	}

	/* get a list of DSs in this RRD file */
	snprintf(query, BUFSIZE, "select data_source_name,rrd_heartbeat,rrd_minimum,rrd_maximum,data_source_type_id from data_template_rrd where local_data_id=%i", local_data_id);

	result = db_query(mysql, query);

	/* loop through each DS */
	for (i=0; i<mysql_num_rows(result); i++) {
		row = mysql_fetch_row(result);

		data_source_type_id = (atoi(row[4]) - 1);
		snprintf(temp, sizeof(temp), "DS:%s:%s:%s:%s:%s ", row[0], ds[data_source_type_id], row[1], row[2], ((atoi(row[3]) == 0) ? "U" : row[3]));

		strncat(ds_string, temp, BUFSIZE);
	}

	/* free memory */
	mysql_free_result(result);

	/* build final rrd create string */
	snprintf(rrdcmd, 2048, "create '%s' --step %i %s %s", data_source_path, rrd_step, ds_string, rra_string);

	return rrdcmd;
}

char *rrdcmd_multids(multi_rrd_t *multi_targets, int multi_target_count) {
	char logmessage[255];
	int i;
	char part1[256] = "", part2[256] = "";
	char *rrdcmd = (char *) malloc(BUFSIZE);
	char temp[256];

	MYSQL_RES *result;

	if (multi_target_count > 15) {
		sprintf(logmessage,"ERROR: Too many data sources in this RRD! (%i), trimming to 15\n", multi_target_count);
		cacti_log(logmessage,"e");
		multi_target_count = 15;
	}

	for(i=0; i<=multi_target_count; i++) {
		if(i!=0) strncat(part1, ":", sizeof(part1));
		strncat(part1, multi_targets[i].rrd_name, sizeof(part1));
		snprintf(temp, sizeof(temp), ":%s", multi_targets[i].result);
		strncat(part2, temp, sizeof(part2));
	}

	snprintf(rrdcmd, BUFSIZE, "update '%s' --template %s N%s", multi_targets[0].rrd_path, part1, part2);

	return rrdcmd;
}

char *rrdcmd_lli(char *rrd_name, char *rrd_path, char *result) {
	char *rrdcmd = (char *) malloc(BUFSIZE);
	snprintf(rrdcmd, BUFSIZE, "update '%s' --template %s N:%s", rrd_path, rrd_name, result);

	return rrdcmd;
}

char *rrdcmd_string(char *rrd_path, char *stringresult, int local_data_id, MYSQL *mysql) {
	char *p, *tokens[64];
	char *rrdcmd = (char *) malloc(BUFSIZE);
	char *last;
	char query[256];
	char logmessage[255];
	int i = 0;
	int j = 0;

	MYSQL_RES *result;
	MYSQL_ROW row;

	snprintf(rrdcmd, BUFSIZE, "%s", "update '");

	for((p = strtok_r(stringresult, " :", &last)); p; (p = strtok_r(NULL, " :", &last)), i++) tokens[i] = p;
	tokens[i] = NULL;

	strncat(rrdcmd, rrd_path, BUFSIZE);
	strncat(rrdcmd, "' --template ", BUFSIZE);

	for (j=0; j<i; j=j+2) {
		if (j!=0) {
			strncat(rrdcmd, ":", BUFSIZE);
		}

		snprintf(query, BUFSIZE, "select rrd_data_source_name from data_input_data_fcache where \
			local_data_id=%i and data_input_field_name=\"%s\"", local_data_id, tokens[j]);

		result = db_query(mysql, query);

		/* make sure to check if the entry actual exists in the 'data_input_data_fcache' table, or cactid
		will segfault */
		if (mysql_num_rows(result) == 0) {
			sprintf(logmessage,"ERROR: Field name '%s' not in field cache!\n", tokens[j]);
			cacti_log(logmessage,"e");
			strncat(rrdcmd, tokens[j], BUFSIZE);
		}else{
			row = mysql_fetch_row(result);
			strncat(rrdcmd, row[0], BUFSIZE);
			
			if (set.verbose >= HIGH) {
				printf("RRDCMD: MULTI expansion: found fieldname: %s, found rrdname: %s, local_data_id: %i\n", row[0], tokens[j], local_data_id);
			}
		}
	}

	/* free memory */
	mysql_free_result(result);

	strncat(rrdcmd, " N", BUFSIZE);

	for(j=1; j<i; j=j+2) {
		strncat(rrdcmd, ":", BUFSIZE);
		strncat(rrdcmd, tokens[j], BUFSIZE);
	}

	return rrdcmd;
}

char *get_rrdtool_path(MYSQL *mysql) {
	MYSQL_RES *result;
	MYSQL_ROW row;

	static char rrdtool_path[128];
	char query[256];

	snprintf(query, sizeof(query), "select value from settings where name='path_rrdtool'");

	result = db_query(mysql, query);

	if (mysql_num_rows(result) == 0) {
		snprintf(rrdtool_path, sizeof(rrdtool_path), "%s", "rrdtool -");
	}else{
		row = mysql_fetch_row(result);
		snprintf(rrdtool_path, sizeof(rrdtool_path), "%s -", row[0]);
	}

	/* free memory */
	mysql_free_result(result);

	return rrdtool_path;
}
