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

-- Actual CREATE TABLE statements from Cacti/cacti 8d5f404ea5beed56d50c4533bae01e5d5f0db026

SET SESSION sql_mode='';

CREATE TABLE host (
  id mediumint(8) unsigned NOT NULL auto_increment,
  poller_id int(10) unsigned NOT NULL default '1',
  site_id int(10) unsigned NOT NULL default '1',
  host_template_id mediumint(8) unsigned NOT NULL default '0',
  description varchar(150) NOT NULL default '',
  hostname varchar(100) default NULL,
  location varchar(40) default NULL,
  notes text,
  external_id varchar(40) default NULL,
  snmp_community varchar(100) default NULL,
  snmp_version tinyint(3) unsigned NOT NULL default '1',
  snmp_username varchar(50) default NULL,
  snmp_password varchar(50) default NULL,
  snmp_auth_protocol char(6) default '',
  snmp_priv_passphrase varchar(200) default '',
  snmp_priv_protocol char(7) default '',
  snmp_context varchar(64) default '',
  snmp_engine_id varchar(64) default '',
  snmp_port mediumint(8) unsigned NOT NULL default '161',
  snmp_timeout mediumint(8) unsigned NOT NULL default '500',
  snmp_sysDescr varchar(300) NOT NULL default '',
  snmp_sysObjectID varchar(128) NOT NULL default '',
  snmp_sysUpTimeInstance bigint(20) unsigned NOT NULL default '0',
  snmp_sysContact varchar(300) NOT NULL default '',
  snmp_sysName varchar(300) NOT NULL default '',
  snmp_sysLocation varchar(300) NOT NULL default '',
  availability_method smallint(5) unsigned NOT NULL default '1',
  ping_method smallint(5) unsigned default '0',
  ping_port int(10) unsigned default '0',
  ping_timeout int(10) unsigned default '500',
  ping_retries int(10) unsigned default '2',
  max_oids int(10) unsigned default '10',
  bulk_walk_size int(11) DEFAULT '-1',
  device_threads tinyint(3) unsigned NOT NULL DEFAULT '1',
  deleted char(2) NOT NULL default '',
  disabled char(2) NOT NULL default '',
  status tinyint(3) unsigned NOT NULL default '0',
  status_event_count mediumint(8) unsigned NOT NULL default '0',
  status_fail_date timestamp NOT NULL default '0000-00-00 00:00:00',
  status_rec_date timestamp NOT NULL default '0000-00-00 00:00:00',
  status_last_error varchar(255) default '',
  min_time decimal(10,5) default '9.99999',
  max_time decimal(10,5) default '0.00000',
  cur_time decimal(10,5) default '0.00000',
  avg_time decimal(10,5) default '0.00000',
  polling_time DOUBLE default '0',
  total_polls int(10) unsigned default '0',
  failed_polls int(10) unsigned default '0',
  availability decimal(8,5) NOT NULL default '100.00000',
  last_updated timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY poller_id_disabled (poller_id, disabled),
  KEY external_id (external_id),
  KEY disabled (disabled),
  KEY status (status),
  KEY site_id_location (site_id, location),
  KEY hostname (hostname),
  KEY poller_id_last_updated (poller_id, last_updated)
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
  `last_updated` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
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

CREATE TABLE poller_output (
  local_data_id int(10) unsigned NOT NULL default '0',
  rrd_name varchar(19) NOT NULL default '',
  time timestamp NOT NULL default '0000-00-00 00:00:00',
  output varchar(512) NOT NULL default '',
  PRIMARY KEY (local_data_id, rrd_name, time) /*!50060 USING BTREE */
) ENGINE=MEMORY;

CREATE TABLE `poller_output_boost` (
  `local_data_id` int(10) unsigned NOT NULL default '0',
  `rrd_name` varchar(19) NOT NULL default '',
  `time` timestamp NOT NULL default '0000-00-00 00:00:00',
  `output` varchar(512) NOT NULL,
  PRIMARY KEY USING BTREE (`local_data_id`, `time`, `rrd_name`)
) ENGINE=InnoDB ROW_FORMAT=Dynamic;

CREATE TABLE poller_reindex (
  host_id mediumint(8) unsigned NOT NULL default '0',
  data_query_id mediumint(8) unsigned NOT NULL default '0',
  action tinyint(3) unsigned NOT NULL default '0',
  present tinyint(3) unsigned NOT NULL DEFAULT '1',
  op char(1) NOT NULL default '',
  assert_value varchar(100) NOT NULL default '',
  arg1 varchar(255) NOT NULL default '',
  PRIMARY KEY (host_id, data_query_id, arg1(187)),
  KEY present (present)
) ENGINE=InnoDB ROW_FORMAT=Dynamic;

CREATE TABLE poller_time (
  id bigint(20) unsigned NOT NULL auto_increment,
  pid int(10) unsigned NOT NULL default '0',
  poller_id int(10) unsigned NOT NULL default '1',
  start_time timestamp NOT NULL default '0000-00-00 00:00:00',
  end_time timestamp NOT NULL default '0000-00-00 00:00:00',
  PRIMARY KEY (id),
  KEY `poller_id_end_time` (`poller_id`, `end_time`)
) ENGINE=InnoDB ROW_FORMAT=Dynamic;

CREATE TABLE poller_command (
  poller_id smallint(5) unsigned NOT NULL default '1',
  time timestamp NOT NULL default '0000-00-00 00:00:00',
  action tinyint(3) unsigned NOT NULL default '0',
  command varchar(191) NOT NULL default '',
  last_updated timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (poller_id, action, command),
  KEY poller_id_last_updated (poller_id, last_updated)
) ENGINE=InnoDB ROW_FORMAT=Dynamic;

CREATE TABLE settings (
  name varchar(255) NOT NULL default '',
  value varchar(4096) NOT NULL default '',
  PRIMARY KEY (name)
) ENGINE=InnoDB ROW_FORMAT=Dynamic;

CREATE TABLE version (
  cacti char(20) default '',
  PRIMARY KEY (cacti)
) ENGINE=InnoDB ROW_FORMAT=Dynamic;
