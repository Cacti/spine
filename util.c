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

#include <sys/stat.h>
#include <syslog.h>
#include "common.h"
#include "cactid.h"
#include "util.h"

/* read configuration file to establish local environment */
int read_cactid_config(char *file, config_t * set) {
	FILE *fp;
	char buff[BUFSIZE];
	char p1[BUFSIZE];
	char p2[BUFSIZE];

	if ((fp = fopen(file, "rb")) == NULL) {
		printf("ERROR: Could not open config file.\n");
		return (-1);
	}else{
		if (set->verbose >= HIGH) {
			printf("UTIL: Using cactid config file [%s].\n", file);
		}
		
		while(!feof(fp)) {
			fgets(buff, BUFSIZE, fp);
			if (!feof(fp) && *buff != '#' && *buff != ' ' && *buff != '\n') {
				sscanf(buff, "%20s %255s", p1, p2);

				if (!strcasecmp(p1, "Interval")) set->interval = atoi(p2);
				else if (!strcasecmp(p1, "SNMP_Ver")) set->snmp_ver = atoi(p2);
				else if (!strcasecmp(p1, "LogFile")) strncpy(set->logfile, p2, sizeof(set->logfile));
				else if (!strcasecmp(p1, "Verbose")) set->verbose = atoi(p2);
				else if (!strcasecmp(p1, "Threads")) set->threads = atoi(p2);
				else if (!strcasecmp(p1, "PHP_Server")) strncpy(set->path_php_server, p2, sizeof(set->path_php_server));
				else if (!strcasecmp(p1, "DB_Host")) strncpy(set->dbhost, p2, sizeof(set->dbhost));
				else if (!strcasecmp(p1, "DB_Database")) strncpy(set->dbdb, p2, sizeof(set->dbdb));
				else if (!strcasecmp(p1, "DB_User")) strncpy(set->dbuser, p2, sizeof(set->dbuser));
				else if (!strcasecmp(p1, "DB_Pass")) strncpy(set->dbpass, p2, sizeof(set->dbpass));
				else {
					printf("UTIL: ERROR - Unrecongized directive: %s=%s in %s\n", 
					p1, p2, file);
					exit(-1);
				}
			}
		}

		if (set->snmp_ver != 1 && set->snmp_ver != 2) {
			printf("UTIL: Unsupported SNMP version: %d.\n", set->snmp_ver);
			exit(-1);
		}

		if (set->threads < 1 || set->threads > MAX_THREADS) {
			printf("UTIL: Invalid Number of Threads: %d (max=%d).\n", 
			set->threads, MAX_THREADS);
			exit(-1);
		}

		return (0);
	}
}

/* populate master configuration defaults */
void config_defaults(config_t * set) {
	set->interval = DEFAULT_INTERVAL;
	set->snmp_ver = DEFAULT_SNMP_VER;
	set->threads = DEFAULT_THREADS;

	strncpy(set->dbhost, DEFAULT_DB_HOST, sizeof(set->dbhost));
	strncpy(set->dbdb, DEFAULT_DB_DB, sizeof(set->dbhost));
	strncpy(set->dbuser, DEFAULT_DB_USER, sizeof(set->dbhost));
	strncpy(set->dbpass, DEFAULT_DB_PASS, sizeof(set->dbhost));
	strncpy(set->logfile, DEFAULT_Log_File, sizeof(set->logfile));

	strncpy(config_paths[0], CONFIG_PATH_1, sizeof(config_paths[0]));
	strncpy(config_paths[1], CONFIG_PATH_2, sizeof(config_paths[2]));
	strncpy(config_paths[2], CONFIG_PATH_3, sizeof(config_paths[3]));
	strncpy(config_paths[3], CONFIG_PATH_4, sizeof(config_paths[4]));
	strncpy(config_paths[4], CONFIG_PATH_5, sizeof(config_paths[5]));

	return;
}

/* cacti log file handler */
int cacti_log(char *logmessage) {
    FILE *log_file;

    /* Variables for Time Display */
    time_t nowbin;
    const struct tm *nowstruct;

    char flogmessage[256];	/* Formatted Log Message */
    char syslog_cmd[256];	/* Syslog Command */
    extern config_t set;
    int attempts = 0;
    int fileopen = 0;
    int severity = 0;

    if ((set.log_destination == 1) || (set.log_destination == 2)) {
 		while (!fileopen) {
			if (!file_exists(set.logfile)) {
				log_file = fopen(set.logfile, "w");
			}else {
           		log_file = fopen(set.logfile, "a");
			}

           	if (log_file != NULL) {
           		fileopen = 1;
        	}else {
           		printf("ERROR: Could not open Logfile will not be logging.\n");
				break;
     		}
      	}
  	}

	/* get time for logfile */
    if (time(&nowbin) == (time_t) - 1)
       	printf("ERROR: Could not get time of day from time()\n");

    nowstruct = localtime(&nowbin);

    if (strftime(flogmessage, 50, "%m/%d/%Y %I:%M %p - ", nowstruct) == (size_t) 0)
    	printf("ERROR: Could not get string from strftime()\n");

	/* concatenate time to log message */
	strcat(flogmessage, logmessage);

    if ( fileopen != 0 ) {
		fputs(flogmessage, log_file);
        fclose(log_file);
	}

	/* output to syslog/eventlog */
	if ((set.log_destination == 2) || (set.log_destination == 3)) {
		openlog("Cacti Logging", LOG_PERROR | LOG_NDELAY | LOG_PID, LOG_SYSLOG);
		if ((strstr(flogmessage,"ERROR")) && (set.log_perror)) {
			syslog(LOG_CRIT,"%s\n", flogmessage);
		}
		if ((strstr(flogmessage,"STATS")) && (set.log_pstats)){
	            syslog(LOG_NOTICE,"%s\n", flogmessage);
		}
		closelog();
	}

	if (set.verbose >= HIGH) {
		printf(logmessage);
	}
}

/* check for a file name */
int file_exists(char *filename) {
	struct stat file_stat;

	if (stat(filename, &file_stat)) {
		return 0;
	}else{
		return 1;
	}
}

/* retreive timestamp for logging */
void timestamp(char *str) {
	struct timeval now;
	struct tm *t;

	gettimeofday(&now, NULL);
	t = localtime(&now.tv_sec);
	printf("[%02d/%02d %02d:%02d:%02d %s]\n", t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, str);

	return;
}

/* verify is a number for error processing */
int is_number(char *string) {
	int i;

	for(i=0; i<strlen(string); i++) {
		if(!isdigit(string[i]) && !(i==strlen(string)-1 && isspace(string[i]))) return(0);
	}

	return(1);
}

/* convert a string to an argc/argv combination */
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

/* change backslashes to forward slashes for system calls */
char *clean_string( char *string_to_clean ) {
    char *posptr;

    posptr = strchr(string_to_clean,'\\');

	while(posptr != NULL)
	{
		*posptr = '/';
    	posptr = strchr(string_to_clean,'\\');
    }

	return(string_to_clean);
}

