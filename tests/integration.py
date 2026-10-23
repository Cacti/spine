#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The Cacti Group
"""Run real Spine processes against a disposable schema on an isolated server."""
import configparser
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
BINARY = Path(os.environ.get('SPINE_TEST_BINARY', ROOT.parent / 'spine')).resolve()
FAULT_BINARY = Path(os.environ.get('SPINE_TEST_FAULT_BINARY', ROOT / 'spine_alloc_fault')).resolve()
CLIENT = shutil.which('mariadb') or shutil.which('mysql')


class Polling(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not CLIENT:
            raise RuntimeError('A MariaDB or MySQL CLI client is required')
        config = os.environ.get('SPINE_TEST_DB_CONFIG')
        if not config:
            raise RuntimeError('Set SPINE_TEST_DB_CONFIG to a private client config for an isolated test server')
        cls.client_config = Path(config).resolve()
        if cls.client_config.stat().st_mode & 0o077:
            raise RuntimeError('The database client config must have mode 0600')
        ini = configparser.ConfigParser()
        ini.read(cls.client_config)
        cls.host = ini['client'].get('host', '127.0.0.1')
        cls.port = int(ini['client'].get('port', '3306'))
        if any(c.isspace() for c in cls.host):
            raise RuntimeError('Invalid test database host')
        cls.database = 'spine_test_' + secrets.token_hex(6)
        cls.user = 'spine_test_' + secrets.token_hex(6)
        cls.password = secrets.token_hex(24)
        cls.directory = Path(tempfile.mkdtemp(prefix='spine-regression-'))
        cls.addClassCleanup(shutil.rmtree, cls.directory)
        cls.sql('CREATE DATABASE ' + cls.database + ';', database=False)
        cls.addClassCleanup(cls.sql, 'DROP DATABASE IF EXISTS ' + cls.database + ';', False)
        cls.sql(f"CREATE USER '{cls.user}'@'%' IDENTIFIED BY '{cls.password}';"
                f"GRANT SELECT,INSERT,UPDATE,DELETE ON {cls.database}.* TO '{cls.user}'@'%';", False)
        cls.addClassCleanup(cls.sql, f"DROP USER IF EXISTS '{cls.user}'@'%';", False)
        cacti_source = os.environ.get('SPINE_TEST_CACTI_ROOT')
        cls.cacti = None
        if cacti_source:
            source = Path(cacti_source).resolve()
            for name in ('cacti.sql', 'script_server.php', 'include/global.php'):
                if not (source / name).is_file():
                    raise RuntimeError('Incomplete Cacti source: ' + name)
            cls.cacti = cls.directory / 'cacti'
            shutil.copytree(source, cls.cacti)
            cls.sql((source / 'cacti.sql').read_text())
            php_config = cls.cacti / 'include/config.php'
            php_config.touch(mode=0o600, exist_ok=True)
            php_config.chmod(0o600)
            # Random credentials and the validated hostname contain no PHP syntax.
            if not all(c.isalnum() or c in '_.:-' for c in cls.host):
                raise RuntimeError('Invalid PHP fixture database hostname')
            php_config.write_text("<?php\n" +
                f"$database_type='mysql'; $database_default='{cls.database}';\n"
                f"$database_hostname='{cls.host}'; $database_port={cls.port};\n"
                f"$database_username='{cls.user}'; $database_password='{cls.password}';\n"
                "$database_retries=1; $database_ssl=false; $database_persist=false;\n"
                "$poller_id=1; $url_path='/'; $cacti_session_name='CactiRegression';\n")
            (cls.cacti / 'scripts/ss_spine_regression.php').write_text(
                '<?php\n// SPDX-License-Identifier: GPL-2.0-or-later\n'
                '// Copyright (C) 2026 The Cacti Group\n'
                'function ss_spine_regression($id) { return (string)(int)$id; }\n')
        else:
            cls.sql((ROOT / 'schema.sql').read_text())
        conf = cls.directory / 'spine.conf'
        conf.touch(mode=0o600)
        conf.write_text(f'DB_Host {cls.host}\nDB_Port {cls.port}\nDB_Database {cls.database}\n'
                        f'DB_User {cls.user}\nDB_Pass {cls.password}\n')
        cls.conf = conf
        cls.script = cls.directory / 'respond.sh'
        cls.script.write_text('#!/bin/sh\nif [ "${2:-0}" != 0 ]; then sleep "$2"; fi\nprintf "%s\\n" "$1"\n')
        cls.script.chmod(0o755)
        webroot = cls.cacti or cls.directory
        cls.sql("REPLACE INTO version VALUES ('1.2.32'); INSERT INTO poller(id,threads) VALUES(1,16) "
                "ON DUPLICATE KEY UPDATE threads=VALUES(threads);"
                "INSERT INTO settings(name,value) VALUES"
                f"('path_webroot','{webroot}'),('path_cactilog','{cls.directory}/cacti.log'),"
                "('path_php_binary','/usr/bin/php'),('php_servers','10'),('script_timeout','5'),"
                "('poller_interval','1800'),('active_profiles','0'),('total_snmp_ports','1'),"
                "('log_verbosity','1'),('spine_log_level','1'),('concurrent_processes','1') "
                "ON DUPLICATE KEY UPDATE value=VALUES(value);"
                "CREATE TABLE audit_expected(host_id INT,local_data_id INT,rrd_name VARCHAR(19),"
                "PRIMARY KEY(local_data_id,rrd_name));"
                "CREATE TABLE audit_first(host_id INT PRIMARY KEY,local_data_id INT,rrd_name VARCHAR(19));"
                "CREATE TABLE audit_schedule(host_id INT,output_rows INT);"
                "CREATE TABLE audit_duplicates(attempts INT); INSERT INTO audit_duplicates VALUES(0);\n"
                "DELIMITER //\n"
                "CREATE TRIGGER audit_output AFTER UPDATE ON poller_output FOR EACH ROW "
                "UPDATE audit_duplicates SET attempts=attempts+1//\n"
                "CREATE TRIGGER audit_schedule_change BEFORE UPDATE ON poller_item FOR EACH ROW BEGIN "
                "IF OLD.rrd_next_step<>NEW.rrd_next_step AND EXISTS(SELECT 1 FROM audit_first "
                "WHERE host_id=OLD.host_id AND local_data_id=OLD.local_data_id AND rrd_name=OLD.rrd_name) THEN "
                "INSERT INTO audit_schedule SELECT OLD.host_id,COUNT(*) FROM poller_output AS po "
                "JOIN audit_expected AS ex ON po.local_data_id=ex.local_data_id AND po.rrd_name=ex.rrd_name "
                "WHERE ex.host_id=OLD.host_id; END IF; END//\nDELIMITER ;\n")

    @classmethod
    def sql(cls, statement, database=True):
        args = [CLIENT, '--defaults-extra-file=' + str(cls.client_config),
                '--batch', '--raw', '--skip-column-names']
        if database:
            args.append(cls.database)
        # Cacti's maintenance schema uses zero-date defaults. Match Spine's
        # session adjustment without changing the test server's global mode.
        statement = ("SET SESSION sql_mode=REPLACE(REPLACE(@@sql_mode,'NO_ZERO_DATE',''),'NO_ZERO_IN_DATE','');\n"
                     + statement)
        result = subprocess.run(args, input=statement, text=True, capture_output=True, timeout=60)
        if result.returncode:
            raise RuntimeError('Test database operation failed: ' + result.stderr[-2000:])
        return result.stdout.strip()

    def setUp(self):
        self.sql('SET GLOBAL general_log=OFF;', False)
        self.sql('DROP TRIGGER IF EXISTS injected_write_failure; TRUNCATE poller_item; TRUNCATE host; '
                 'TRUNCATE poller_output; TRUNCATE poller_time; TRUNCATE audit_schedule; '
                 'TRUNCATE audit_expected; TRUNCATE audit_first; UPDATE audit_duplicates SET attempts=0; '
                 "UPDATE settings SET value='0' WHERE name='active_profiles';"
                 "UPDATE settings SET value='1' WHERE name='total_snmp_ports';"
                 "UPDATE settings SET value='1800' WHERE name='poller_interval';")
        self.addCleanup(self.sql, 'SET GLOBAL general_log=OFF;', False)

    def seed(self, count=37, threads=10, host=1, profiles=False, multi=False, delayed=False, foreign=False):
        if host:
            self.sql('INSERT INTO host(id,poller_id,hostname,snmp_version,availability_method,status,device_threads) '
                     f"VALUES({host},1,'127.0.0.1',0,0,3,{threads});")
        if profiles:
            self.sql("UPDATE settings SET value='1' WHERE name='active_profiles';")
        values = []
        for i in range(count):
            source = host * 10000 + i + 1
            for name in (('a', 'b') if multi else ('value',)):
                step = 1800 if profiles else 0
                command = str(self.script) + ' ' + str(source) + (' 0.2' if delayed and i == 0 else '')
                poller = 2 if foreign and i == count - 1 else 1
                values.append(f"({source},{host},{poller},1,'',0,'{name}',3600,{step},'{command}')")
        if values:
            self.sql('INSERT INTO poller_item(local_data_id,host_id,poller_id,action,hostname,snmp_version,'
                     'rrd_name,rrd_step,rrd_next_step,arg1) VALUES' + ','.join(values) + ';')
        self.sql('INSERT INTO audit_expected SELECT host_id,local_data_id,rrd_name FROM poller_item '
                 'WHERE poller_id=1' + ('' if profiles else ' AND rrd_next_step<=0') +
                 ' ON DUPLICATE KEY UPDATE host_id=VALUES(host_id);')
        self.sql('INSERT IGNORE INTO audit_first SELECT host_id,local_data_id,rrd_name FROM audit_expected '
                 'ORDER BY local_data_id,rrd_name;')

    def run_spine(self, failure=None, ping=False):
        self.sql("SET GLOBAL log_output='TABLE'; TRUNCATE mysql.general_log; SET GLOBAL general_log=ON;", False)
        args = [str(FAULT_BINARY if failure else BINARY), '--conf=' + str(self.conf), '-p', '1', '-t', '16', '-S', '-V', '1']
        if ping:
            args.append('-P')
        env = os.environ.copy()
        if failure:
            env['SPINE_TEST_ALLOC_FAILURE'] = failure
        result = subprocess.run(args, env=env, text=True, capture_output=True, timeout=30)
        self.sql('SET GLOBAL general_log=OFF;', False)
        self.assertIn(result.returncode, (0, 1), result.stdout[-3000:] + result.stderr[-3000:])
        self.result = result
        return result

    def check_complete(self, devices=1, schedule=True):
        self.assertEqual(self.result.returncode, 0, self.result.stdout[-3000:])
        self.assertEqual(self.sql('SELECT COUNT(*) FROM poller_output;'), self.sql('SELECT COUNT(*) FROM audit_expected;'),
                         self.result.stdout[-3000:] + self.result.stderr[-1000:])
        self.assertEqual(self.sql('SELECT COUNT(*) FROM audit_expected ex LEFT JOIN poller_output po '
                                 'ON po.local_data_id=ex.local_data_id AND po.rrd_name=ex.rrd_name '
                                 'WHERE po.local_data_id IS NULL OR po.output<>CAST(ex.local_data_id AS CHAR);'), '0')
        self.assertEqual(self.sql('SELECT attempts FROM audit_duplicates;'), '0')
        counts = self.sql("SELECT COUNT(*) FROM mysql.general_log WHERE command_type='Query' AND "
                          "argument LIKE 'SELECT SQL_NO_CACHE COUNT(local_data_id) FROM poller_item%';", False)
        self.assertEqual(int(counts), devices)
        if schedule:
            self.assertEqual(int(self.sql('SELECT COUNT(*) FROM audit_schedule;')), devices)
            self.assertEqual(self.sql('SELECT COUNT(*) FROM audit_schedule s WHERE output_rows<>('
                                     'SELECT COUNT(*) FROM audit_expected ex WHERE ex.host_id=s.host_id);'), '0')

    def test_single_and_ten_workers(self):
        for threads in (1, 10):
            with self.subTest(threads=threads):
                self.setUp()
                self.seed(37, threads)
                self.run_spine()
                self.check_complete()

    def test_fewer_items_than_workers(self):
        self.seed(3, 10)
        self.run_spine()
        self.check_complete()

    def test_empty_device(self):
        self.seed(0, 10)
        self.run_spine()
        self.check_complete(schedule=False)

    def test_multiple_devices(self):
        self.seed(37, 10, host=1)
        self.seed(13, 10, host=2)
        self.run_spine()
        self.check_complete(devices=2)

    def test_multiple_rows_per_source(self):
        self.seed(37, 10, multi=True)
        self.run_spine()
        self.check_complete()

    def test_multiple_ports_and_rows(self):
        self.seed(103, 10, multi=True)
        self.sql("UPDATE settings SET value='2' WHERE name='total_snmp_ports';"
                 'UPDATE poller_item SET snmp_port=IF(MOD(local_data_id,2)=0,161,1161);')
        self.run_spine()
        self.check_complete()

    def test_zero_interval_uses_default(self):
        self.seed(37, 10)
        self.sql("UPDATE settings SET value='0' WHERE name='poller_interval';"
                 'UPDATE poller_item SET rrd_next_step=1800 WHERE local_data_id=10037; '
                 'DELETE FROM audit_expected WHERE local_data_id=10037;')
        self.run_spine()
        self.check_complete()

    def test_active_profiles(self):
        for threads in (1, 10):
            with self.subTest(threads=threads):
                self.setUp()
                self.seed(37, threads, profiles=True)
                self.sql('UPDATE poller_item SET rrd_next_step=0 WHERE MOD(local_data_id,2)=0;')
                self.run_spine()
                self.check_complete(schedule=False)

    def test_poller_filter(self):
        self.seed(37, 10, foreign=True)
        self.run_spine()
        self.check_complete()

    def test_completion_order(self):
        self.seed(37, 10, delayed=True)
        self.run_spine()
        self.check_complete()

    def test_mixed_eligibility(self):
        self.seed(37, 10)
        self.sql('UPDATE poller_item SET rrd_next_step=1800 WHERE MOD(local_data_id,2)=0; '
                 'DELETE ex FROM audit_expected ex JOIN poller_item pi '
                 'ON pi.local_data_id=ex.local_data_id AND pi.rrd_name=ex.rrd_name WHERE pi.rrd_next_step>0;')
        self.run_spine()
        self.check_complete()

    def test_device_zero(self):
        self.seed(13, 10, host=0)
        self.seed(37, 10, host=1)
        self.run_spine()
        self.check_complete(devices=2)

    def test_output_write_failure(self):
        self.seed(37, 10)
        self.sql("DELIMITER //\nCREATE TRIGGER injected_write_failure BEFORE INSERT ON poller_output "
                 "FOR EACH ROW BEGIN IF NEW.local_data_id=10037 THEN SIGNAL SQLSTATE '45000' "
                 "SET MESSAGE_TEXT='injected output failure'; END IF; END//\nDELIMITER ;\n")
        self.run_spine()
        self.assertEqual(self.result.returncode, 1)
        self.assertEqual(self.sql('SELECT COUNT(*) FROM audit_schedule;'), '0')
        self.assertEqual(self.sql('SELECT COUNT(*) FROM poller_item WHERE rrd_next_step<>0;'), '0')
        count = int(self.sql('SELECT COUNT(*) FROM poller_output;'))
        self.assertGreater(count, 0)
        self.assertLess(count, 37)

    def test_ping_only_skips_item_count(self):
        self.seed(37, 10)
        self.run_spine(ping=True)
        self.assertEqual(self.result.returncode, 0)
        self.assertEqual(self.sql('SELECT COUNT(*) FROM poller_output;'), '0')
        self.assertEqual(self.sql("SELECT COUNT(*) FROM mysql.general_log WHERE command_type='Query' AND "
                                  "argument LIKE 'SELECT SQL_NO_CACHE COUNT(local_data_id) FROM poller_item%';", False), '0')

    def test_allocation_failures_and_retry(self):
        for failure in ('target', 'target-once', 'snmp', 'snmp-once'):
            with self.subTest(failure=failure):
                self.setUp()
                self.seed(100, 10)
                self.run_spine(failure=failure)
                self.assertEqual(self.result.returncode, 1, self.result.stdout[-3000:])
                self.assertIn('Unable to allocate', self.result.stdout)
                self.assertEqual(self.sql('SELECT COUNT(*) FROM audit_schedule;'), '0')
                self.assertEqual(self.sql('SELECT COUNT(*) FROM poller_item WHERE rrd_next_step<>0;'), '0')
                count = int(self.sql('SELECT COUNT(*) FROM poller_output;'))
                if failure.endswith('-once'):
                    self.assertGreater(count, 0)
                    self.assertLess(count, 100)
                else:
                    self.assertEqual(count, 0)
                self.sql('TRUNCATE poller_output; TRUNCATE audit_schedule; UPDATE audit_duplicates SET attempts=0;')
                self.run_spine()
                self.check_complete()

    @unittest.skipUnless(os.environ.get('SPINE_TEST_CACTI_ROOT'), 'requires a complete upstream Cacti source tree')
    def test_real_script_server_pool(self):
        for pool in (1, 10, 15):
            with self.subTest(pool=pool):
                self.setUp()
                self.seed(103, 10)
                command = str(self.cacti / 'scripts/ss_spine_regression.php') + ' ss_spine_regression '
                self.sql("UPDATE settings SET value='" + str(pool) + "' WHERE name='php_servers';"
                         "UPDATE poller_item SET action=2,arg1=CONCAT('" + command + "',local_data_id);")
                self.run_spine()
                self.check_complete()

    @unittest.skipUnless(os.environ.get('SPINE_TEST_CACTI_ROOT'), 'requires a complete upstream Cacti source tree')
    def test_real_script_server_mixed_with_shell(self):
        self.seed(103, 10, multi=True)
        command = str(self.cacti / 'scripts/ss_spine_regression.php') + ' ss_spine_regression '
        self.sql("UPDATE poller_item SET action=2,arg1=CONCAT('" + command + "',local_data_id) "
                 "WHERE MOD(local_data_id,2)=0;")
        self.run_spine()
        self.check_complete()


if __name__ == '__main__':
    unittest.main(verbosity=2)
