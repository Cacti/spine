/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2003 Ian Berry                                            |
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
 |    - Rivo Nurges (rrd support, mysql poller cache, misc functions)      |
 |    - RTG (core poller code, pthreads, snmp, autoconf examples)          |
 +-------------------------------------------------------------------------+
 | - raXnet - http://www.raxnet.net/                                       |
 +-------------------------------------------------------------------------+
*/

#include "common.h"
#include "cactid.h"

int update_rrd(rrd_t *rrd_targets, int rrd_target_count) {
	int i;
	FILE *rrdtool_stdin;
	char rrdcmd[512];
	char **rrdargv;
	int rrdargc;
	
	#ifndef RRD
	rrdtool_stdin=popen("rrdtool -", "w");
	#endif
	
	for(i=0; i<rrd_target_count; i++) {
		printf("rrdcmd: %s\n", rrd_targets[i].rrdcmd);
		#ifdef RRD
		sprintf(rrdcmd,"%s", rrd_targets[i].rrdcmd);
		rrdargv = string_to_argv(rrdcmd, &rrdargc);
		rrd_update(rrdargc, rrdargv);
		free(rrdargv);
		#else
		fprintf(rrdtool_stdin, "%s\n",rrd_targets[i].rrdcmd);
		#endif
	}
	
	#ifndef RRD
	pclose(rrdtool_stdin);
	#endif
}

void create_rrd(int local_data_id, char *data_source_path) {
	MYSQL mysql;
	MYSQL_RES *result;
	MYSQL_ROW row;
	FILE *rrdtool_stdin;
	
	int i;
	int consolidation_function_id, data_source_type_id, rrd_step;
	char query[512];
	char rra_string[512] = "";
	char ds_string[512] = "";
	char rrdcmd[512];
	char temp[64];
	char *cf[4] = {"AVERAGE", "MIN", "MAX", "LAST"};
	char *ds[4] = {"GAUGE", "COUNTER", "DERIVE", "ABSOLUTE"};
	
	/* get a list of RRAs in this RRD file */
	sprintf(query, "select data_template_data.rrd_step,rra.x_files_factor,rra.steps,rra.rows,rra_cf.consolidation_function_id,(rra.rows*rra.steps) as rra_order from data_template_data left join data_template_data_rra on data_template_data.id=data_template_data_rra.data_template_data_id left join rra on data_template_data_rra.rra_id=rra.id left join rra_cf on rra.id=rra_cf.rra_id where data_template_data.local_data_id=%i and (rra.steps is not null or rra.rows is not null) order by rra_cf.consolidation_function_id,rra_order", local_data_id);
	
	rtg_dbconnect(set.dbdb, &mysql);
	result = db_query(&mysql, query);
	
	/* loop through each RRA */
	for (i=0; i<mysql_num_rows(result); i++) {
		row = mysql_fetch_row(result);
		
		consolidation_function_id = (atoi(row[4]) - 1);
		sprintf(temp,"RRA:%s:%s:%s:%s ", cf[consolidation_function_id], row[1], row[2], row[3]);
		
		strcat(rra_string,temp);
		
		rrd_step = atoi(row[0]);
	}
	
	/* free memory */
	free(result);
	
	/* get a list of DSs in this RRD file */
	sprintf(query, "select data_source_name,rrd_heartbeat,rrd_minimum,rrd_maximum,data_source_type_id from data_template_rrd where local_data_id=%i", local_data_id);
	
	result = db_query(&mysql, query);
	
	/* loop through each DS */
	for (i=0; i<mysql_num_rows(result); i++) {
		row = mysql_fetch_row(result);
		
		data_source_type_id = (atoi(row[4]) - 1);
		sprintf(temp,"DS:%s:%s:%s:%s:%s ", row[0], ds[data_source_type_id], row[1], row[2], row[3]);
		
		strcat(ds_string,temp);
	}
	
	/* free memory */
	free(result);
	mysql_close(&mysql);
	
	/* build final rrd create string */
	sprintf(rrdcmd, "create %s --step %i %s %s", data_source_path, rrd_step, ds_string, rra_string);
	
	/* run the rrd create string against rrdtool */
	rrdtool_stdin = popen("rrdtool -", "w");
	fprintf(rrdtool_stdin, "%s\n",rrdcmd);
	pclose(rrdtool_stdin);
	
	printf("rrdcmd: %s\n", rrdcmd);
}

char *rrdcmd_multids(multi_rrd_t *multi_targets, int multi_target_count) {
	int i;
	char part1[64]="", part2[64]="";
	char rrdcmd[512];
	char temp[64];
	
	for(i=0; i<=multi_target_count; i++) {
		if(i!=0) strcat(part1, ":");
		strcat(part1, multi_targets[i].rrd_name);
		sprintf(temp, ":%s", multi_targets[i].result);
		strcat(part2, temp);
	}
	
	sprintf(rrdcmd, "update %s --template %s N%s", multi_targets[0].rrd_path, part1, part2);
	
	return rrdcmd;
}

char *rrdcmd_lli(char *rrd_name, char *rrd_path, char *result) {
	char rrdcmd[512];
	sprintf(rrdcmd, "update %s --template %s N:%s", rrd_path, rrd_name, result);
	
	return rrdcmd;
}

char *rrdcmd_string(char *rrd_path, char *stringresult, int local_data_id){
	char *p, *tokens[64];
	char rrdcmd[512] ="update ";
	char *last;
	char query[256];
	int i = 0;
	int j = 0;
	
	MYSQL mysql;
	MYSQL_RES *result;
	MYSQL_ROW row;
	
	mysql_init(&mysql);
	
	if (!mysql_real_connect(&mysql, set.dbhost, set.dbuser, set.dbpass, set.dbdb, 0, NULL, 0)) {
		fprintf(stderr, "%s\n", mysql_error(&mysql));
		exit(1);
	}
	
	for((p = strtok_r(stringresult, " :", &last)); p; (p = strtok_r(NULL, " :", &last)), i++) tokens[i] = p;
	tokens[i] = NULL;
	
	strcat(rrdcmd, rrd_path);
	strcat(rrdcmd, " --template ");
	for (j=0; j<i; j=j+2) {
		if (j!=0) {
			strcat(rrdcmd, ":");
		}
		
		sprintf(query, "select rrd_data_source_name from data_input_data_fcache where \
			local_data_id=%i and data_input_field_name=\"%s\"", local_data_id, tokens[j]);
		
		if (mysql_query(&mysql, query)) {
			fprintf(stderr, "Error in query\n");
		}
		
		if ((result = mysql_store_result(&mysql)) == NULL) {
			fprintf(stderr, "Error retrieving data\n");
			exit(1);
		}
		
		/* make sure to check if the entry actual exists in the 'data_input_data_fcache' table, or cactid
		will segfault */
		if (mysql_num_rows(result) == 0) {
			printf("ERROR: Field name '%s' not in field cache!\n", tokens[j]);
			strcat(rrdcmd, tokens[j]);
		}else{
			row = mysql_fetch_row(result);
			strcat(rrdcmd, row[0]);
			
			printf("MULTI expansion: found fieldname: %s, found rrdname: %s, local_data_id: %i\n", row[0], tokens[j], local_data_id);
		}
	}
	
	mysql_close(&mysql);
	strcat(rrdcmd, " N");
	
	for(j=1; j<i; j=j+2) {
		strcat(rrdcmd, ":");
		strcat(rrdcmd, tokens[j]);
	}
	
	return rrdcmd;
}
