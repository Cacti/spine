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
#include <sys/stat.h>

/* read configuration file to establish local environment */
int read_rtg_config(char *file, config_t * set) {
	FILE *fp;
	char buff[BUFSIZE];
	char p1[BUFSIZE];
	char p2[BUFSIZE];
	
	if ((fp = fopen(file, "r")) == NULL) {
		return (-1);
	}else{
		if (set->verbose >= LOW) {
			printf("\nReading RTG config [%s].\n", file);
		}
		
		while(!feof(fp)) {
			fgets(buff, BUFSIZE, fp);
			
			if (!feof(fp) && *buff != '#' && *buff != ' ' && *buff != '\n') {
				sscanf(buff, "%s %s", p1, p2);
				if (!strcasecmp(p1, "Interval")) set->interval = atoi(p2);
				else if (!strcasecmp(p1, "SNMP_Ver")) set->snmp_ver = atoi(p2);
				else if (!strcasecmp(p1, "Threads")) set->threads = atoi(p2);
				else if (!strcasecmp(p1, "DB_Host")) strcpy(set->dbhost, p2);
				else if (!strcasecmp(p1, "DB_Database")) strcpy(set->dbdb, p2);
				else if (!strcasecmp(p1, "DB_User")) strcpy(set->dbuser, p2);
				else if (!strcasecmp(p1, "DB_Pass")) strcpy(set->dbpass, p2);
				
				/* Long longs not ANSI C.  If OS doesn't support atoll() use default. */
				else if (!strcasecmp(p1, "OutOfRange")) 
					#ifdef HAVE_LONG_LONG_SCANF
					set->out_of_range = atoll(p2);
					#else
					set->out_of_range = DEFAULT_OUT_OF_RANGE;
					#endif
				else { 
					printf("*** Unrecongized directive: %s=%s in %s\n", 
					p1, p2, file);
					exit(-1);
				}
			}
		}
		
		if (set->snmp_ver != 1 && set->snmp_ver != 2) {
			printf("*** Unsupported SNMP version: %d.\n", set->snmp_ver);
			exit(-1);
		}
		
		if (set->threads < 1 || set->threads > MAX_THREADS) {
			printf("*** Invalid Number of Threads: %d (max=%d).\n", 
			set->threads, MAX_THREADS);
			exit(-1);
		}
		return (0);
	}
}



/* Populate Master Configuration Defaults */
void config_defaults(config_t * set) {
	set->interval = DEFAULT_INTERVAL;
	set->out_of_range = DEFAULT_OUT_OF_RANGE;
	set->snmp_ver = DEFAULT_SNMP_VER;
	set->threads = DEFAULT_THREADS;
	strcpy(set->dbhost, DEFAULT_DB_HOST);
	strcpy(set->dbdb, DEFAULT_DB_DB);
	strcpy(set->dbuser, DEFAULT_DB_USER);
	strcpy(set->dbpass, DEFAULT_DB_PASS);
	
	return;
}

/* Print RTG stats */
void print_stats(stats_t stats) {
	printf("\n[Polls = %lld] [DBInserts = %lld] [Wraps = %d] [OutOfRange = %d]\n",
		stats.polls, stats.db_inserts, stats.wraps, stats.out_of_range);
	printf("[No Resp = %d] [SNMP Errs = %d] [Slow = %d] [PollTime = %2.3f%c]\n",
		stats.no_resp, stats.errors, stats.slow, stats.poll_time, 's');
	
	return;
}


/* A fancy sleep routine */
void sleepy(float sleep_time) {
	int chunks = 10;
	int i;
	
	if (sleep_time > chunks) {
		if (set.verbose >= LOW) {
			printf("Next Poll: ");
		}
		
		for (i = chunks; i > 0; i--) {
			if (set.verbose >= LOW) {
				printf("%d...", i);
				fflush(NULL);
			}
			
			usleep(sleep_time*1000000 / chunks);
		}
		
		if (set.verbose >= LOW) printf("\n");
	}else{
		sleep_time*=1000000;
		usleep(sleep_time);
	}
	
	return;
}

int file_exists(char *filename) {
	struct stat file_stat;
	
	if (stat(filename, &file_stat)) {
		return 0;
	}else{
		return 1;
	}
}

/* Timestamp */
void timestamp(char *str) {
	struct timeval now;
	struct tm *t;
	
	gettimeofday(&now, NULL);
	t = localtime(&now.tv_sec);
	printf("[%02d/%02d %02d:%02d:%02d %s]\n", t->tm_mon + 1, 
	t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, str);
	
	return;
}

int is_number (char *string) {
	int i;
	
	for(i=0; i<strlen(string); i++) {
		if(!isdigit(string[i]) && !(i==strlen(string)-1 && isspace(string[i]))) return(0);
	}
	
	return(1);
}

char **string_to_argv(char *argstring, int *argc){
	char *p, **argv;
	char *last;
	int i = 0;
	
	for((*argc)=1, i=0; i<strlen(argstring); i++) if(argstring[i]==' ') (*argc)++;
	
	argv = (char **)malloc((*argc) * sizeof(char**));
	for((p = strtok_r(argstring, " ", &last)), i=0; p; (p = strtok_r(NULL, " ", &last)), i++) argv[i] = p;
	argv[i] = NULL;
	
	return argv;
}
