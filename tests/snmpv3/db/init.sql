-- Minimal Cacti schema for Spine SNMPv3 test fixture.
-- Only the tables and columns that spine actually queries.

CREATE TABLE IF NOT EXISTS `settings` (
  `name`  varchar(50)   NOT NULL DEFAULT '',
  `value` varchar(2048) DEFAULT NULL,
  PRIMARY KEY (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `poller` (
  `id`      smallint(5) unsigned NOT NULL AUTO_INCREMENT,
  `name`    varchar(30)          NOT NULL DEFAULT '',
  `threads` int(10) unsigned     NOT NULL DEFAULT 2,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `host` (
  `id`                    mediumint(8) unsigned NOT NULL AUTO_INCREMENT,
  `hostname`              varchar(100)          NOT NULL DEFAULT '',
  `snmp_community`        varchar(100)          NOT NULL DEFAULT '',
  `snmp_version`          tinyint(1) unsigned   NOT NULL DEFAULT 1,
  `snmp_username`         varchar(50)           NOT NULL DEFAULT '',
  `snmp_password`         varchar(50)           NOT NULL DEFAULT '',
  `snmp_auth_protocol`    char(7)               NOT NULL DEFAULT '',
  `snmp_priv_passphrase`  varchar(200)          NOT NULL DEFAULT '',
  `snmp_priv_protocol`    char(6)               NOT NULL DEFAULT '',
  `snmp_context`          varchar(64)           NOT NULL DEFAULT '',
  `snmp_engine_id`        varchar(64)           NOT NULL DEFAULT '',
  `snmp_port`             mediumint(5) unsigned NOT NULL DEFAULT 1161,
  `snmp_timeout`          int(10) unsigned      NOT NULL DEFAULT 500,
  `max_oids`              int(12) unsigned      DEFAULT 10,
  `availability_method`   smallint(5) unsigned  NOT NULL DEFAULT 2,
  `ping_method`           smallint(5) unsigned  DEFAULT 0,
  `ping_port`             int(12) unsigned      DEFAULT 0,
  `ping_timeout`          int(12) unsigned      DEFAULT 400,
  `ping_retries`          int(12) unsigned      DEFAULT 1,
  `status`                tinyint(2)            NOT NULL DEFAULT 0,
  `status_event_count`    smallint(5) unsigned  NOT NULL DEFAULT 0,
  `status_fail_date`      timestamp             NOT NULL DEFAULT '0000-00-00 00:00:00',
  `status_rec_date`       timestamp             NOT NULL DEFAULT '0000-00-00 00:00:00',
  `status_last_error`     varchar(255)          DEFAULT '',
  `min_time`              decimal(10,5)         DEFAULT 9.99999,
  `max_time`              decimal(10,5)         DEFAULT 0.00000,
  `cur_time`              decimal(10,5)         DEFAULT 0.00000,
  `avg_time`              decimal(10,5)         DEFAULT 0.00000,
  `total_polls`           int(12) unsigned      DEFAULT 0,
  `failed_polls`          int(12) unsigned      DEFAULT 0,
  `availability`          decimal(8,5)          NOT NULL DEFAULT 100.00000,
  `polling_time`          double                DEFAULT 0,
  `snmp_sysUpTimeInstance` bigint(20) unsigned  DEFAULT 0,
  `snmp_sysDescr`         varchar(300)          DEFAULT '',
  `snmp_sysObjectID`      varchar(128)          DEFAULT '',
  `snmp_sysContact`       varchar(300)          DEFAULT '',
  `snmp_sysName`          varchar(300)          DEFAULT '',
  `snmp_sysLocation`      varchar(300)          DEFAULT '',
  `disabled`              char(2)               NOT NULL DEFAULT '',
  `deleted`               char(2)               NOT NULL DEFAULT '',
  `device_threads`        tinyint(2) unsigned   NOT NULL DEFAULT 1,
  `poller_id`             smallint(5) unsigned  NOT NULL DEFAULT 1,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `poller_item` (
  `local_data_id`        mediumint(8) unsigned NOT NULL DEFAULT 0,
  `host_id`              mediumint(8) unsigned NOT NULL DEFAULT 0,
  `action`               tinyint(2)            NOT NULL DEFAULT 1,
  `hostname`             varchar(100)          NOT NULL DEFAULT '',
  `snmp_community`       varchar(100)          NOT NULL DEFAULT '',
  `snmp_version`         tinyint(1) unsigned   NOT NULL DEFAULT 0,
  `snmp_username`        varchar(50)           NOT NULL DEFAULT '',
  `snmp_password`        varchar(50)           NOT NULL DEFAULT '',
  `snmp_auth_protocol`   char(7)               NOT NULL DEFAULT '',
  `snmp_priv_passphrase` varchar(200)          NOT NULL DEFAULT '',
  `snmp_priv_protocol`   char(6)               NOT NULL DEFAULT '',
  `snmp_context`         varchar(64)           NOT NULL DEFAULT '',
  `snmp_engine_id`       varchar(64)           NOT NULL DEFAULT '',
  `snmp_port`            mediumint(5) unsigned NOT NULL DEFAULT 1161,
  `snmp_timeout`         int(10) unsigned      NOT NULL DEFAULT 500,
  `rrd_name`             varchar(19)           NOT NULL DEFAULT '',
  `rrd_path`             varchar(255)          NOT NULL DEFAULT '',
  `rrd_num`              tinyint(2) unsigned   DEFAULT 0,
  `rrd_step`             mediumint(8)          NOT NULL DEFAULT 300,
  `arg1`                 text,
  `arg2`                 varchar(255)          DEFAULT NULL,
  `arg3`                 varchar(255)          DEFAULT NULL,
  `rrd_next_step`        int(10)               NOT NULL DEFAULT 0,
  `deleted`              char(2)               NOT NULL DEFAULT '',
  `poller_id`            smallint(5) unsigned  NOT NULL DEFAULT 1,
  PRIMARY KEY (`local_data_id`, `poller_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `poller_reindex` (
  `host_id`       mediumint(8) unsigned NOT NULL DEFAULT 0,
  `data_query_id` mediumint(8) unsigned NOT NULL DEFAULT 0,
  `action`        tinyint(2)            NOT NULL DEFAULT 0,
  `op`            char(1)               NOT NULL DEFAULT '',
  `assert_value`  varchar(100)          NOT NULL DEFAULT '',
  `arg1`          varchar(255)          NOT NULL DEFAULT '',
  PRIMARY KEY (`host_id`, `data_query_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `version` (
  `cacti` varchar(20) NOT NULL DEFAULT '',
  PRIMARY KEY (`cacti`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `poller_time` (
  `id`         mediumint(8) unsigned NOT NULL AUTO_INCREMENT,
  `poller_id`  smallint(5) unsigned  NOT NULL DEFAULT 0,
  `pid`        int(10) unsigned      NOT NULL DEFAULT 0,
  `start_time` timestamp             NOT NULL DEFAULT current_timestamp(),
  `end_time`   timestamp             NOT NULL DEFAULT '0000-00-00 00:00:00',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `poller_output` (
  `local_data_id` mediumint(8) unsigned NOT NULL DEFAULT 0,
  `rrd_name`      varchar(19)           NOT NULL DEFAULT '',
  `time`          timestamp             NOT NULL DEFAULT current_timestamp(),
  `output`        text                  NOT NULL,
  PRIMARY KEY (`local_data_id`, `rrd_name`, `time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `poller_output_boost` (
  `local_data_id` mediumint(8) unsigned NOT NULL DEFAULT 0,
  `rrd_name`      varchar(19)           NOT NULL DEFAULT '',
  `time`          timestamp             NOT NULL DEFAULT current_timestamp(),
  `output`        mediumtext,
  PRIMARY KEY (`local_data_id`, `rrd_name`, `time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `host_errors` (
  `host_id`       mediumint(8) unsigned NOT NULL DEFAULT 0,
  `poller_id`     smallint(5) unsigned  NOT NULL DEFAULT 0,
  `errors`        int(10) unsigned      NOT NULL DEFAULT 0,
  `local_data_ids` text,
  PRIMARY KEY (`host_id`, `poller_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `poller_command` (
  `poller_id` smallint(5) unsigned NOT NULL DEFAULT 0,
  `time`      timestamp            NOT NULL DEFAULT current_timestamp(),
  `action`    tinyint(2)           NOT NULL DEFAULT 0,
  `command`   varchar(255)         NOT NULL DEFAULT '',
  PRIMARY KEY (`poller_id`, `action`, `command`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- -------------------------------------------------------------------------
-- Seed data
-- -------------------------------------------------------------------------

INSERT INTO `version` (`cacti`) VALUES ('1.3.0');

INSERT INTO `poller` (`id`, `name`) VALUES (1, 'Main Poller');

-- Key spine runtime settings
INSERT INTO `settings` (`name`, `value`) VALUES
  ('poller_id',               '1'),
  ('poller_interval',         '300'),
  ('log_verbosity',           '5'),     -- MEDIUM: shows USM WARNING messages
  ('availability_method',     '2'),     -- SNMP uptime
  ('ping_method',             '0'),
  ('snmp_ver',                '3'),
  ('log_destination',         '4'),     -- stdout (LOGDEST_STDOUT)
  ('selective_device_debug',  ''),
  ('device_threads',          '1'),
  ('max_get_size',            '10'),
  ('spine_log_level',         '5');

-- TEST CREDENTIALS ONLY -- never use these values outside this fixture.
-- SNMPv3 test host pointing at the snmpd container (hostname resolves via
-- Docker's internal DNS to the 'snmpd' service).
INSERT INTO `host` (
  `id`, `hostname`, `snmp_community`,
  `snmp_version`, `snmp_username`, `snmp_password`,
  `snmp_auth_protocol`, `snmp_priv_passphrase`, `snmp_priv_protocol`,
  `snmp_context`, `snmp_engine_id`,
  `snmp_port`, `snmp_timeout`, `max_oids`,
  `availability_method`, `ping_method`, `ping_port`, `ping_timeout`, `ping_retries`,
  `status`, `poller_id`, `device_threads`, `deleted`
) VALUES (
  1, 'snmpd', 'public',
  3, 'testuser', 'authpass1234',
  'SHA-256', 'privpass1234', 'AES',
  '', '',
  1161, 1000, 10,
  2, 0, 0, 400, 1,
  3, 1, 1, ''  -- status=3 (HOST_UP per poller.h HOST_UP constant)
);

-- One poller_item: query sysUpTime (.1.3.6.1.2.1.1.3.0) via SNMPv3
INSERT INTO `poller_item` (
  `local_data_id`, `host_id`, `action`,
  `hostname`, `snmp_community`,
  `snmp_version`, `snmp_username`, `snmp_password`,
  `snmp_auth_protocol`, `snmp_priv_passphrase`, `snmp_priv_protocol`,
  `snmp_context`, `snmp_engine_id`,
  `snmp_port`, `snmp_timeout`,
  `rrd_name`, `rrd_path`, `rrd_num`, `rrd_step`,
  `arg1`, `deleted`, `poller_id`
) VALUES (
  1, 1, 0,
  'snmpd', 'public',
  3, 'testuser', 'authpass1234',
  'SHA-256', 'privpass1234', 'AES',
  '', '',
  1161, 1000,
  'uptime', '/dev/null', 1, 300,
  '.1.3.6.1.2.1.1.3.0', '', 1
);
