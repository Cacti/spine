/*
  +-------------------------------------------------------------------------+
  | Copyright (C) 2004-2026 The Cacti Group                                 |
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
  | Cacti: The Complete RRDTool-based Graphing Solution                     |
  +-------------------------------------------------------------------------+
  | This code is designed, written, and maintained by the Cacti Group. See  |
  | about.php and/or the AUTHORS file for specific developer information.   |
  +-------------------------------------------------------------------------+
  | http://www.cacti.net/                                                   |
  +-------------------------------------------------------------------------+
*/

-- Schema excerpt from Cacti cacti.sql; isolated regression fixtures only.
CREATE TABLE settings (
  name varchar(255) NOT NULL default '',
  value varchar(4096) NOT NULL default '',
  PRIMARY KEY (name)
) ENGINE=InnoDB ROW_FORMAT=Dynamic;

CREATE TABLE `poller` (
  `id` smallint(5) unsigned NOT NULL AUTO_INCREMENT,
  `disabled` char(2) DEFAULT '',
  `name` varchar(30) DEFAULT NULL,
  `notes` varchar(1024) DEFAULT '',
  `status` int(10) unsigned NOT NULL DEFAULT '0',
  `timezone` varchar(40) DEFAULT '',
  `hostname` varchar(100) NOT NULL DEFAULT '',
  `dbdefault` varchar(20) NOT NULL DEFAULT '',
  `dbhost` varchar(64) NOT NULL DEFAULT '',
  `dbuser` varchar(20) NOT NULL DEFAULT '',
  `dbpass` varchar(64) NOT NULL DEFAULT '',
  `dbport` int(10) unsigned DEFAULT '3306',
  `dbretries` int(10) unsigned DEFAULT '2',
  `dbssl` char(3) DEFAULT '',
  `dbsslkey` varchar(255) DEFAULT NULL,
  `dbsslcert` varchar(255) DEFAULT NULL,
  `dbsslca` varchar(255) DEFAULT NULL,
  `total_time` double DEFAULT '0',
  `max_time` double DEFAULT NULL,
  `min_time` double DEFAULT NULL,
  `avg_time` double DEFAULT NULL,
  `total_polls` int(10) unsigned DEFAULT '0',
  `processes` int(10) unsigned DEFAULT '1',
  `threads` int(10) unsigned DEFAULT '1',
  `sync_interval` int(10) unsigned DEFAULT '7200',
  `snmp` mediumint(8) unsigned DEFAULT '0',
  `script` mediumint(8) unsigned DEFAULT '0',
  `server` mediumint(8) unsigned DEFAULT '0',
  `last_update` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `last_status` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `last_sync` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `requires_sync` char(2) DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `name` (`name`),
  KEY `disabled` (`disabled`)
) ENGINE=InnoDB ROW_FORMAT=Dynamic COMMENT='Pollers for Cacti';

CREATE TABLE poller_item (
  `local_data_id` int(10) unsigned NOT NULL default '0',
  `poller_id` int(10) unsigned NOT NULL default '1',
  `host_id` mediumint(8) unsigned NOT NULL default '0',
  `action` tinyint(3) unsigned NOT NULL default '1',
  `present` tinyint(3) unsigned NOT NULL DEFAULT '1',
  `last_updated` timestamp DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `hostname` varchar(100) NOT NULL default '',
  `snmp_community` varchar(100) NOT NULL default '',
  `snmp_version` tinyint(3) unsigned NOT NULL default '0',
  `snmp_username` varchar(50) NOT NULL default '',
  `snmp_password` varchar(50) NOT NULL default '',
  `snmp_auth_protocol` char(6) NOT NULL default '',
  `snmp_priv_passphrase` varchar(200) NOT NULL default '',
  `snmp_priv_protocol` char(7) NOT NULL default '',
  `snmp_context` varchar(64) default '',
  `snmp_engine_id` varchar(64) default '',
  `snmp_port` mediumint(8) unsigned NOT NULL default '161',
  `snmp_timeout` mediumint(8) unsigned NOT NULL default '0',
  `rrd_name` varchar(19) NOT NULL default '',
  `rrd_path` varchar(255) NOT NULL default '',
  `rrd_num` tinyint(3) unsigned NOT NULL default '0',
  `rrd_step` mediumint(8) NOT NULL default '300',
  `rrd_next_step` mediumint(8) NOT NULL default '0',
  `arg1` TEXT,
  `arg2` varchar(255) default NULL,
  `arg3` varchar(255) default NULL,
  PRIMARY KEY (`local_data_id`,`rrd_name`),
  KEY `host_id` (`host_id`),
  KEY `action` (`action`),
  KEY `present` (`present`),
  KEY `poller_id_host_id` (`poller_id`,`host_id`),
  KEY `poller_id_rrd_next_step` (`poller_id`,`rrd_next_step`),
  KEY `poller_id_action` (`poller_id`,`action`),
  KEY `poller_id_last_updated` (`poller_id`, `last_updated`)
) ENGINE=InnoDB ROW_FORMAT=Dynamic;

CREATE TABLE version (
  cacti char(20) default '',
  PRIMARY KEY (cacti)
) ENGINE=InnoDB ROW_FORMAT=Dynamic;
INSERT INTO version VALUES ('1.2.32');
INSERT INTO poller (id,threads) VALUES (1,7);
