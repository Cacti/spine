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

#include <poll.h>
#include "common.h"
#include "cactid.h"
#include "locks.h"
#include "nft_popen.h"
#include "util.h"

int php_fd; /* File Descriptor for PHP Pipe Processing */
FILE *php_file; /* File for PHP Scripting */

int php_init() {
    php_fd = nft_popen(set.phppath, "w");
    if (php_fd < 0) {
    	cacti_log("ERROR: Problem opening PHP for Scripting.\n","e");
   	} else {
   	    php_file = fdopen(php_fd, "w");
   	    if (php_file == NULL) {
   	        cacti_log("ERROR: Could not open PHP for Write.\n","e");
        } else {
           	if (set.verbose >= HIGH) {
           		printf("PHP: PHP Stream File Descriptor Active, return code was %i\n", php_fd);
      		}
  		}
  	}

   	return php_fd;
}

int php_close() {
	nft_pclose(php_fd);
}

int php_cmd( char * php_command ) {
    int result;
}

