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

-- Schema excerpt from Cacti develop cacti.sql; isolated poller regressions.
CREATE TABLE `host` (
  id mediumint(8) unsigned NOT NULL auto_increment,
  poller_id int(10) unsigned NOT NULL default '1',
  site_id int(10) unsigned NOT NULL default '1',
  host_template_id mediumint(8) unsigned NOT NULL default '0',
  description varchar(150) NOT NULL default '',
  hostname varchar(100) default NULL,
  location varchar(40) default NULL,
  notes text,
  external_id varchar(40) default NULL,
  snmp_options tinyint(3) unsigned NOT NULL default '0',
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
  snmp_retries tinyint(3) unsigned NOT NULL default '3',
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
  bulk_walk_size int(11) default '-1',
  device_threads tinyint(3) unsigned NOT NULL default '1',
  deleted char(2) NOT NULL default '',
  disabled char(2) NOT NULL default '',
  graphs int(10) unsigned NOT NULL default '0',
  data_sources int(10) unsigned NOT NULL default '0',
  status tinyint(3) unsigned NOT NULL default '0',
  status_event_count mediumint(8) unsigned NOT NULL default '0',
  status_fail_date timestamp NOT NULL default '0000-00-00 00:00:00',
  status_rec_date timestamp NOT NULL default '0000-00-00 00:00:00',
  status_options_date timestamp NOT NULL default '0000-00-00 00:00:00',
  status_last_error varchar(255) default '',
  min_time decimal(10,5) default '9.99999',
  max_time decimal(10,5) default '0.00000',
  cur_time decimal(10,5) default '0.00000',
  avg_time decimal(10,5) default '0.00000',
  polling_time DOUBLE default '0',
  current_errors int(10) unsigned NOT NULL default '0',
  total_polls int(10) unsigned default '0',
  failed_polls int(10) unsigned default '0',
  availability decimal(8,5) NOT NULL default '100.00000',
  last_updated timestamp default CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  created timestamp default CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY poller_id_disabled (poller_id, disabled),
  KEY host_template_id (host_template_id),
  KEY external_id (external_id),
  KEY disabled (disabled),
  KEY status (status),
  KEY current_errors (current_errors),
  KEY site_id_location (site_id, location),
  KEY hostname (hostname),
  KEY poller_id_last_updated (poller_id, last_updated)
) ENGINE=InnoDB ROW_FORMAT=Dynamic;

CREATE TABLE `poller_reindex` (
  host_id mediumint(8) unsigned NOT NULL default '0',
  data_query_id mediumint(8) unsigned NOT NULL default '0',
  action tinyint(3) unsigned NOT NULL default '0',
  present tinyint(3) unsigned NOT NULL default '1',
  op char(1) NOT NULL default '',
  assert_value varchar(100) NOT NULL default '',
  arg1 varchar(255) NOT NULL default '',
  PRIMARY KEY (host_id, data_query_id, arg1(187)),
  KEY present (present)
) ENGINE=InnoDB ROW_FORMAT=Dynamic;

CREATE TABLE `poller_output` (
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
  `last_updated` timestamp NOT NULL default current_timestamp,
  PRIMARY KEY USING BTREE (`local_data_id`, `time`, `rrd_name`),
  KEY `last_updated` (`last_updated`),
  KEY `time` (`time`)
) ENGINE=InnoDB ROW_FORMAT=Dynamic;

CREATE TABLE `host_errors` (
  `host_id` mediumint(8) unsigned NOT NULL default 0,
  `poller_id` int(10) unsigned NOT NULL default 1,
  `errors` mediumint(8) unsigned NOT NULL default 0,
  `local_data_ids` text default NULL,
  PRIMARY KEY (`host_id`),
  KEY `poller_id` (`poller_id`)
) ENGINE=InnoDB ROW_FORMAT=DYNAMIC COMMENT='Holds Device Error buffer for Spine';

CREATE TABLE `poller_command` (
  poller_id smallint(5) unsigned NOT NULL default '1',
  time timestamp NOT NULL default '0000-00-00 00:00:00',
  action tinyint(3) unsigned NOT NULL default '0',
  command varchar(191) NOT NULL default '',
  last_updated timestamp default CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (poller_id, action, command),
  KEY poller_id_last_updated (poller_id, last_updated)
) ENGINE=InnoDB ROW_FORMAT=Dynamic;

CREATE TABLE `poller_time` (
  id bigint(20) unsigned NOT NULL auto_increment,
  pid int(10) unsigned NOT NULL default '0',
  poller_id int(10) unsigned NOT NULL default '1',
  start_time timestamp NOT NULL default '0000-00-00 00:00:00',
  end_time timestamp NOT NULL default '0000-00-00 00:00:00',
  PRIMARY KEY (id),
  KEY `poller_id_end_time` (`poller_id`, `end_time`)
) ENGINE=InnoDB ROW_FORMAT=Dynamic;
