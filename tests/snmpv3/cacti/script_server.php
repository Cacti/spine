<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU Lesser General Public License      |
 | as published by the Free Software Foundation; either version 2.1       |
 | of the License, or (at your option) any later version.                  |
 +-------------------------------------------------------------------------+
 */

/* Minimal Cacti script-server protocol fixture for Spine integration tests. */

fwrite(STDOUT, "Started\n");
fflush(STDOUT);

while (($line = fgets(STDIN)) !== false) {
	$command = trim($line);
	if ($command === 'quit') {
		break;
	}

	fwrite(STDOUT, $command === 'ss_test.php ss_value 1' ? "42\n" : "U\n");
	fflush(STDOUT);
}
