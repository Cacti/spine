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
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parent
BINARY = Path(os.environ.get('SPINE_TEST_BINARY', ROOT.parent / 'spine')).resolve()
FAULT_BINARY = Path(os.environ.get('SPINE_TEST_FAULT_BINARY', ROOT / 'spine_alloc_fault')).resolve()
# Linking the fault binary needs a linker with --wrap; see configure.ac.
HAVE_FAULT_BINARY = FAULT_BINARY.is_file()
CLIENT = shutil.which('mariadb') or shutil.which('mysql')
# A net-snmp snmpd executable; the tests start their own agent with it.
SNMPD = os.environ.get('SPINE_TEST_SNMPD')
# Optional cases that must run instead of being skipped, as a comma separated
# list, for a CI job that provides their prerequisites.
OPTIONAL = {'cacti', 'fault', 'snmpd'}
REQUIRED = {name.strip() for name in os.environ.get('SPINE_TEST_REQUIRE', '').split(',') if name.strip()}
if REQUIRED - OPTIONAL:
    raise SystemExit('Unknown SPINE_TEST_REQUIRE entries: ' + ', '.join(sorted(REQUIRED - OPTIONAL)))


def optional(name, available, reason):
    """Skip a case whose prerequisite is missing, unless SPINE_TEST_REQUIRE
    names it, in which case the case fails instead."""
    if available or name not in REQUIRED:
        return unittest.skipUnless(available, reason)

    def missing(test):
        def run(self):
            self.fail(reason + ', and SPINE_TEST_REQUIRE requires this case')
        run.__name__ = test.__name__
        return run
    return missing


def icmp_datagram_available():
    # Spine only uses ICMP with root or CAP_NET_RAW; it then tries the
    # datagram socket that net.ipv4.ping_group_range grants first.
    if not sys.platform.startswith('linux') or os.geteuid() != 0:
        return False
    try:
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP).close()
    except OSError:
        return False
    return True


def ber_length(data, i):
    length = data[i]
    if length < 0x80:
        return length, i + 1
    count = length & 0x7f
    return int.from_bytes(data[i + 1:i + 1 + count], 'big'), i + 1 + count


def ber_items(data):
    i = 0
    while i < len(data):
        tag = data[i]
        length, i = ber_length(data, i + 1)
        yield tag, data[i:i + length]
        i += length


def ber(tag, value):
    if len(value) < 0x80:
        return bytes([tag, len(value)]) + value
    size = len(value).to_bytes((len(value).bit_length() + 7) // 8, 'big')
    return bytes([tag, 0x80 | len(size)]) + size + value


def ber_int(value):
    return ber(0x02, value.to_bytes(max(1, (value.bit_length() + 8) // 8), 'big', signed=True))


def oid_text(data):
    parts = [data[0] // 40, data[0] % 40]
    value = 0
    for byte in data[1:]:
        value = (value << 7) | (byte & 0x7f)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    return '.' + '.'.join(map(str, parts))


class SnmpAgent:
    """Answer SNMPv2c GET requests from a table and record each request's OIDs.

    Values are ('int', n), ('ticks', n), ('str', text) or the exception
    values ('noSuchObject',) and ('endOfMibView',); any other OID is
    noSuchInstance.  A request for an OID in errors gets a noSuchName error
    status instead."""

    def __init__(self, values, errors=()):
        self.values = values
        self.errors = errors
        self.requests = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', 0))
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def close(self):
        self.sock.close()

    def encode(self, oid):
        kind, value = (self.values.get(oid, (None,)) + (None,))[:2]
        if kind == 'noSuchObject':
            return ber(0x80, b'')
        if kind == 'endOfMibView':
            return ber(0x82, b'')
        if kind == 'int':
            return ber_int(value)
        if kind == 'ticks':
            return ber(0x43, value.to_bytes(max(1, (value.bit_length() + 8) // 8), 'big'))
        if kind == 'str':
            return ber(0x04, value.encode())
        return ber(0x81, b'')

    def serve(self):
        while True:
            try:
                data, peer = self.sock.recvfrom(65535)
            except OSError:
                return
            (_, message), = ber_items(data)
            version, community, (pdu_tag, pdu) = list(ber_items(message))
            request_id, _, _, (_, bindings) = list(ber_items(pdu))
            oids = [oid_text(list(ber_items(binding))[0][1]) for _, binding in ber_items(bindings)]
            self.requests.append(oids)
            response = ber(0x30, b''.join(ber(0x30, ber(0x06, list(ber_items(binding))[0][1]) + self.encode(oid))
                                          for (_, binding), oid in zip(ber_items(bindings), oids)))
            failed = [i + 1 for i, oid in enumerate(oids) if oid in self.errors]
            pdu = ber(0x02, request_id[1]) + ber_int(2 if failed else 0) + ber_int(failed[0] if failed else 0) + response
            try:
                self.sock.sendto(ber(0x30, ber(*version) + ber(*community) + ber(0xa2, pdu)), peer)
            except OSError:
                return

    def gets(self, oid):
        return sum(request.count(oid) for request in self.requests)


def oid_bytes(text):
    parts = [int(part) for part in text.strip('.').split('.')]
    data = bytes([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7f]
        part >>= 7
        while part:
            chunk.append(0x80 | (part & 0x7f))
            part >>= 7
        data += bytes(reversed(chunk))
    return data


class NetSnmpAgent:
    """Run a real net-snmp snmpd on a loopback port with fixed SNMPv1/v2c and
    SNMPv3 credentials and an integer value under BASE for each given index."""

    BASE = '.1.3.6.1.4.1.8072.9999.9999.7'
    COMMUNITY = 'spine-regression'
    AUTH_USER = 'spineauth'
    PRIV_USER = 'spinepriv'
    AUTH_PASS = 'spine-auth-pass'
    PRIV_PASS = 'spine-priv-pass'

    def __init__(self, directory, indexes):
        self.directory = Path(tempfile.mkdtemp(prefix='snmpd-', dir=directory))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind(('127.0.0.1', 0))
            self.port = probe.getsockname()[1]
        conf = self.directory / 'snmpd.conf'
        conf.write_text(f'agentAddress udp:127.0.0.1:{self.port}\n'
                        f'rocommunity {self.COMMUNITY} 127.0.0.1\n'
                        f'createUser {self.AUTH_USER} SHA "{self.AUTH_PASS}"\n'
                        f'createUser {self.PRIV_USER} SHA "{self.AUTH_PASS}" AES "{self.PRIV_PASS}"\n'
                        f'rouser {self.AUTH_USER} auth\nrouser {self.PRIV_USER} priv\n' +
                        ''.join(f'override {self.BASE}.{i} integer {i}\n' for i in indexes))
        env = dict(os.environ, SNMP_PERSISTENT_DIR=str(self.directory))
        self.process = subprocess.Popen([SNMPD, '-f', '-C', '-c', str(conf), '-Lf', str(self.directory / 'snmpd.log')],
                                        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.wait_ready(indexes[0])

    def wait_ready(self, index):
        oid = ber(0x06, oid_bytes(self.BASE + '.' + str(index)))
        request = ber(0x30, ber_int(1) + ber(0x04, self.COMMUNITY.encode()) +
                      ber(0xa0, ber_int(1) + ber_int(0) + ber_int(0) + ber(0x30, ber(0x30, oid + ber(0x05, b'')))))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(0.2)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    break
                client.sendto(request, ('127.0.0.1', self.port))
                try:
                    client.recvfrom(65535)
                    return
                except OSError:
                    pass
        self.close()
        raise RuntimeError('snmpd did not start: ' + (self.directory / 'snmpd.log').read_text(errors='replace')[-2000:])

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()


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
        # Strict_Mode only adds the non-zero exit status after a failed write.
        cls.strict_conf = cls.directory / 'spine-strict.conf'
        cls.strict_conf.touch(mode=0o600)
        cls.strict_conf.write_text(conf.read_text() + 'Strict_Mode 1\n')
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
                 'TRUNCATE poller_reindex; TRUNCATE poller_command; '
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

    def run_spine(self, failure=None, ping=False, strict=False, hosts=(), conf=None, poller=1):
        self.sql("SET GLOBAL log_output='TABLE'; TRUNCATE mysql.general_log; SET GLOBAL general_log=ON;", False)
        conf = conf or (self.strict_conf if strict else self.conf)
        args = [str(FAULT_BINARY if failure else BINARY), '--conf=' + str(conf), '-p', str(poller), '-t', '16', '-S', '-V', '1']
        if ping:
            args.append('-P')
        args.extend(hosts)
        env = os.environ.copy()
        if failure:
            env['SPINE_TEST_ALLOC_FAILURE'] = failure
        result = subprocess.run(args, env=env, text=True, capture_output=True, timeout=30)
        self.sql('SET GLOBAL general_log=OFF;', False)
        self.assertIn(result.returncode, (0, 1), result.stdout[-3000:] + result.stderr[-3000:])
        self.result = result
        return result

    def check_complete(self, devices=1, schedule=True, device_zero=False):
        self.assertEqual(self.result.returncode, 0, self.result.stdout[-3000:])
        self.assertEqual(self.sql('SELECT COUNT(*) FROM poller_output;'), self.sql('SELECT COUNT(*) FROM audit_expected;'),
                         self.result.stdout[-3000:] + self.result.stderr[-1000:])
        self.assertEqual(self.sql('SELECT COUNT(*) FROM audit_expected ex LEFT JOIN poller_output po '
                                 'ON po.local_data_id=ex.local_data_id AND po.rrd_name=ex.rrd_name '
                                 'WHERE po.local_data_id IS NULL OR CAST(po.output AS BINARY)<>CAST(ex.local_data_id AS BINARY);'), '0')
        self.assertEqual(self.sql('SELECT attempts FROM audit_duplicates;'), '0')
        # The device list carries each device's item count; only device 0,
        # which is not in that list, is counted on its own.
        self.assertEqual(self.general_log_count('SELECT SQL_NO_CACHE id, device_threads,%'), 1)
        self.assertEqual(self.general_log_count('SELECT SQL_NO_CACHE COUNT(local_data_id) FROM poller_item%'),
                         1 if device_zero else 0)
        if schedule:
            self.assertEqual(int(self.sql('SELECT COUNT(*) FROM audit_schedule;')), devices)
            self.assertEqual(self.sql('SELECT COUNT(*) FROM audit_schedule s WHERE output_rows<>('
                                     'SELECT COUNT(*) FROM audit_expected ex WHERE ex.host_id=s.host_id);'), '0')

    def snmp_agent(self, values, availability=2, max_oids=10, errors=()):
        agent = SnmpAgent(values, errors)
        self.addCleanup(agent.close)
        self.sql("UPDATE host SET snmp_version=2,snmp_community='public',snmp_port=" + str(agent.port) +
                 ',snmp_timeout=1000,availability_method=' + str(availability) + ',max_oids=' + str(max_oids) + ';')
        return agent

    def general_log_count(self, pattern):
        return int(self.sql("SELECT COUNT(*) FROM mysql.general_log WHERE command_type='Query' AND "
                            "argument LIKE '" + pattern + "';", False))

    def test_first_partition_owns_availability_and_reindex(self):
        self.seed(37, 10)
        agent = self.snmp_agent({'.1.3.6.1.2.1.1.3.0': ('ticks', 500000), '.1.3.6.1.2.1.2.1.0': ('int', 4)})
        self.sql("INSERT INTO poller_reindex(host_id,data_query_id,action,op,assert_value,arg1) "
                 "VALUES(1,1,0,'=','4','.1.3.6.1.2.1.2.1.0');")
        self.run_spine()
        self.check_complete()
        # one SNMP availability get and one reindex check for ten partitions
        self.assertEqual(agent.gets('.1.3.6.1.2.1.1.3.0'), 1, agent.requests)
        self.assertEqual(agent.gets('.1.3.6.1.2.1.2.1.0'), 1, agent.requests)
        self.assertEqual(self.general_log_count('%FROM poller_reindex%'), 1)
        self.assertEqual(self.sql('SELECT COUNT(*) FROM poller_command;'), '0')
        self.assertEqual(self.sql('SELECT CONCAT(status,":",total_polls,":",failed_polls) FROM host;'), '3:1:0')

    def test_partitions_share_the_restart_verdict(self):
        # an uptime that went backwards stores U in every partition
        self.seed(37, 10)
        agent = self.snmp_agent({'.1.3.6.1.2.1.1.3.0': ('ticks', 500000)})
        self.sql("INSERT INTO poller_reindex(host_id,data_query_id,action,op,assert_value,arg1) "
                 "VALUES(1,1,0,'<','90000000','.1.3.6.1.2.1.1.3.0');")
        self.run_spine()
        self.assertEqual(self.result.returncode, 0, self.result.stdout[-3000:])
        self.assertEqual(self.sql("SELECT COUNT(*) FROM poller_output WHERE output='U';"), '37')
        self.assertEqual(self.sql('SELECT command FROM poller_command;'), '1:1')
        self.assertEqual(self.sql('SELECT assert_value FROM poller_reindex;'), '500000')
        self.assertEqual(self.general_log_count('%FROM poller_reindex%'), 1)
        self.assertLessEqual(len(agent.requests), 3, agent.requests)

    def test_down_device_skips_every_partition(self):
        self.seed(37, 10)
        agent = self.snmp_agent({})
        agent.close()
        self.sql('UPDATE host SET snmp_timeout=200,ping_retries=0;')
        self.run_spine()
        self.assertEqual(self.result.returncode, 0, self.result.stdout[-3000:])
        self.assertEqual(self.sql('SELECT COUNT(*) FROM poller_output;'), '0')
        self.assertEqual(self.sql('SELECT CONCAT(total_polls,":",failed_polls) FROM host;'), '1:1')

    def test_reindex_gets_are_batched(self):
        self.seed(37, 1)
        values = {'.1.3.6.1.2.1.1.3.0': ('ticks', 500000)}
        rows = []
        for i in range(1, 26):
            values['.1.3.6.1.2.1.2.2.1.1.' + str(i)] = ('int', i)
            rows.append(f"(1,1,0,'=','{i}','.1.3.6.1.2.1.2.2.1.1.{i}')")
        # the first mismatch queues a reindex and skips the rest of its data query
        values['.1.3.6.1.2.1.31.1.1.1.1.1'] = ('str', 'eth1')
        rows += ["(1,2,0,'=','eth0','.1.3.6.1.2.1.31.1.1.1.1.1')", "(1,2,0,'=','x','.1.3.6.1.2.1.31.1.1.1.1.2')",
                 "(1,3,0,'<','400000','.1.3.6.1.2.1.1.3.0')"]
        agent = self.snmp_agent(values, availability=0, max_oids=10)
        self.sql('INSERT INTO poller_reindex(host_id,data_query_id,action,op,assert_value,arg1) VALUES' + ','.join(rows) + ';')
        self.run_spine()
        self.check_complete()
        self.assertEqual(self.sql('SELECT command FROM poller_command;'), '1:2')
        self.assertEqual(self.sql("SELECT GROUP_CONCAT(assert_value ORDER BY data_query_id) FROM poller_reindex "
                                  "WHERE data_query_id>1 AND arg1 LIKE '%.1';"), 'eth1')
        self.assertEqual(self.sql('SELECT assert_value FROM poller_reindex WHERE data_query_id=3;'), '500000')
        uptime = ('.1.3.6.1.2.1.1.3.0', '.1.3.6.1.6.3.10.2.1.3.0')
        batched = [r for r in agent.requests if not set(r) & set(uptime)]
        # 27 assertion OIDs in max_oids sized requests, where each took one
        self.assertEqual([len(r) for r in batched], [10, 10, 7], agent.requests)
        self.assertEqual(agent.gets('.1.3.6.1.2.1.1.3.0'), 1, agent.requests)

    def test_reindex_error_status_gets_each_value_alone(self):
        # An error status names one OID; the batch falls back to one get per
        # check, where that OID reads as empty and fails its assertion.
        self.seed(37, 1)
        values = {'.1.3.6.1.2.1.2.2.1.1.' + str(i): ('int', i) for i in range(1, 6)}
        agent = self.snmp_agent(values, availability=0, max_oids=10, errors=('.1.3.6.1.2.1.2.2.1.1.3',))
        self.sql('INSERT INTO poller_reindex(host_id,data_query_id,action,op,assert_value,arg1) VALUES' +
                 ','.join(f"(1,{i},0,'=','{i}','.1.3.6.1.2.1.2.2.1.1.{i}')" for i in range(1, 6)) + ';')
        self.run_spine()
        self.check_complete()
        self.assertEqual(self.sql('SELECT command FROM poller_command;'), '1:3')
        self.assertEqual([len(r) for r in agent.requests if len(r) > 1], [5], agent.requests)
        self.assertEqual(sorted(sum((r for r in agent.requests if len(r) == 1), [])), sorted(values))

    # Cacti's cmd.php reads an assertion OID with an exception value or an
    # error status as U, compares that U with the stored value, queues the
    # reindex when they differ and stores the U, and goes on with the later
    # checks and the device's polling.
    EXCEPTIONS = {'noSuchInstance': None, 'noSuchObject': ('noSuchObject',), 'endOfMibView': ('endOfMibView',)}

    def poll_again(self):
        # the stored U matches on the next cycle, so nothing is queued again
        self.sql('TRUNCATE poller_command; TRUNCATE poller_output; UPDATE poller_item SET rrd_next_step=0;')
        self.run_spine()
        self.check_complete(schedule=False)
        self.assertEqual(self.sql('SELECT COUNT(*) FROM poller_command;'), '0')

    def test_missing_reindex_value_queues_one_reindex(self):
        for name, value in self.EXCEPTIONS.items():
            with self.subTest(exception=name):
                self.setUp()
                self.seed(37, 1)
                values = {'.1.3.6.1.2.1.2.2.1.1.1': ('int', 1), '.1.3.6.1.2.1.2.2.1.1.3': ('int', 9)}
                if value:
                    values['.1.3.6.1.2.1.2.2.1.1.2'] = value
                agent = self.snmp_agent(values, availability=0, max_oids=10)
                self.sql("INSERT INTO poller_reindex(host_id,data_query_id,action,op,assert_value,arg1) VALUES"
                         "(1,1,0,'=','1','.1.3.6.1.2.1.2.2.1.1.1'),(1,2,0,'=','2','.1.3.6.1.2.1.2.2.1.1.2'),"
                         "(1,3,0,'=','3','.1.3.6.1.2.1.2.2.1.1.3');")
                self.run_spine()
                self.check_complete()
                # the missing value queues its reindex and the later check still reads 9
                self.assertEqual(self.sql('SELECT GROUP_CONCAT(command ORDER BY command) FROM poller_command;'), '1:2,1:3')
                self.assertEqual(self.sql('SELECT GROUP_CONCAT(assert_value ORDER BY data_query_id) FROM poller_reindex;'),
                                 '1,U,9')
                self.assertEqual([len(r) for r in agent.requests], [3], agent.requests)
                self.poll_again()

    def test_missing_reindex_value_fetched_alone_queues_one_reindex(self):
        # An error status sends every check to its own get, where that OID
        # and the exception value both read as U.
        for name, value in self.EXCEPTIONS.items():
            with self.subTest(exception=name):
                self.setUp()
                self.seed(37, 1)
                values = {'.1.3.6.1.2.1.2.2.1.1.3': ('int', 9)}
                if value:
                    values['.1.3.6.1.2.1.2.2.1.1.2'] = value
                agent = self.snmp_agent(values, availability=0, max_oids=10, errors=('.1.3.6.1.2.1.2.2.1.1.1',))
                self.sql("INSERT INTO poller_reindex(host_id,data_query_id,action,op,assert_value,arg1) VALUES"
                         "(1,1,0,'=','1','.1.3.6.1.2.1.2.2.1.1.1'),(1,2,0,'=','2','.1.3.6.1.2.1.2.2.1.1.2'),"
                         "(1,3,0,'=','3','.1.3.6.1.2.1.2.2.1.1.3');")
                self.run_spine()
                self.check_complete()
                self.assertEqual(self.sql('SELECT GROUP_CONCAT(command ORDER BY command) FROM poller_command;'),
                                 '1:1,1:2,1:3')
                self.assertEqual(self.sql('SELECT GROUP_CONCAT(assert_value ORDER BY data_query_id) FROM poller_reindex;'),
                                 'U,U,9')
                self.assertEqual([len(r) for r in agent.requests], [3, 1, 1, 1], agent.requests)
                self.poll_again()

    @optional('snmpd', SNMPD, 'set SPINE_TEST_SNMPD to a net-snmp snmpd executable')
    def test_net_snmp_versions_and_security_levels(self):
        # Items are fetched max_oids at a time by snmp_get_multi() and the
        # reindex assertions by the batched gets, over each SNMP version and
        # SNMPv3 security level, from a real agent.
        cases = {
            'v1': (1, {}),
            'v2c': (2, {}),
            'v3 authNoPriv': (3, {'snmp_username': NetSnmpAgent.AUTH_USER, 'snmp_password': NetSnmpAgent.AUTH_PASS,
                                  'snmp_auth_protocol': 'SHA', 'snmp_priv_protocol': '[None]'}),
            'v3 authPriv': (3, {'snmp_username': NetSnmpAgent.PRIV_USER, 'snmp_password': NetSnmpAgent.AUTH_PASS,
                                'snmp_auth_protocol': 'SHA', 'snmp_priv_passphrase': NetSnmpAgent.PRIV_PASS,
                                'snmp_priv_protocol': 'AES'}),
        }
        sources = [10000 + i + 1 for i in range(37)]
        agent = NetSnmpAgent(self.directory, sources)
        self.addCleanup(agent.close)
        base = NetSnmpAgent.BASE
        for name, (version, fields) in cases.items():
            with self.subTest(snmp=name):
                self.setUp()
                self.seed(37, 4)
                settings = {'snmp_version': version, 'snmp_community': NetSnmpAgent.COMMUNITY,
                            'snmp_port': agent.port, 'snmp_timeout': 1000, 'snmp_username': '',
                            'snmp_password': '', 'snmp_auth_protocol': '', 'snmp_priv_passphrase': '',
                            'snmp_priv_protocol': '', **fields}
                # Fixed fixture values; none contain a quote.
                assignments = ','.join(f"{column}='{value}'" for column, value in settings.items())
                self.sql('UPDATE host SET ' + assignments + ',availability_method=2,ping_retries=1,max_oids=10;'
                         'UPDATE poller_item SET ' + assignments +
                         f",action=0,hostname='127.0.0.1',arg1=CONCAT('{base}.',local_data_id);")
                # 25 matching assertions, one that has changed and one whose
                # OID the agent does not have
                rows = [f"(1,1,0,'=','{i}','{base}.{i}')" for i in sources[:25]]
                rows += [f"(1,2,0,'=','0','{base}.{sources[30]}')", f"(1,3,0,'=','7','{base}.99999')"]
                self.sql('INSERT INTO poller_reindex(host_id,data_query_id,action,op,assert_value,arg1) VALUES' +
                         ','.join(rows) + ';')
                self.run_spine()
                self.check_complete()
                self.assertEqual(self.sql('SELECT CONCAT(status,":",total_polls,":",failed_polls) FROM host;'), '3:1:0')
                # SNMPv1 reports the missing OID with a noSuchName error status
                # and later versions with noSuchObject; both read as U, which
                # queues the reindex and is stored.
                self.assertEqual(self.sql('SELECT GROUP_CONCAT(command ORDER BY command) FROM poller_command;'), '1:2,1:3')
                self.assertEqual(self.sql('SELECT assert_value FROM poller_reindex WHERE data_query_id=3;'), 'U')
                self.assertEqual(self.sql('SELECT assert_value FROM poller_reindex WHERE data_query_id=2;'),
                                 str(sources[30]))

    def test_remote_collector_records_its_start_on_the_main_server(self):
        # An online remote collector writes its poller_time row, with a zero
        # end_time, through its main server connection, which needs the same
        # sql_mode relaxation as the local one.  MySQL 5.7 and later reject
        # the zero date by default; require that here on any server.
        self.seed(3, 1)
        self.sql('UPDATE host SET poller_id=2; UPDATE poller_item SET poller_id=2;'
                 'INSERT INTO poller(id,threads) VALUES(2,16) ON DUPLICATE KEY UPDATE threads=VALUES(threads);')
        conf = self.directory / 'spine-remote.conf'
        conf.touch(mode=0o600)
        conf.write_text(self.conf.read_text() + f'RDB_Host {self.host}\nRDB_Port {self.port}\nRDB_Database {self.database}\n'
                        f'RDB_User {self.user}\nRDB_Pass {self.password}\n')
        mode = self.sql('SELECT @@GLOBAL.sql_mode;', False)
        self.addCleanup(self.sql, "SET GLOBAL sql_mode='" + mode + "';", False)
        self.sql("SET GLOBAL sql_mode=CONCAT(@@GLOBAL.sql_mode,',STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE');", False)
        self.run_spine(conf=conf, poller=2)
        self.assertEqual(self.sql("SELECT COUNT(*) FROM poller_time WHERE poller_id=2 AND end_time<>'0000-00-00 00:00:00';"),
                         '1', self.result.stdout[-3000:])

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

    def test_partition_counts_per_device(self):
        # Three devices with different due sets and partition counts, all
        # counted by the one device list query.
        self.seed(37, 10, host=1)
        self.seed(5, 3, host=2)
        self.seed(23, 4, host=3)
        self.sql('UPDATE poller_item SET rrd_next_step=1800 WHERE host_id=3 AND MOD(local_data_id,3)=0; '
                 'DELETE ex FROM audit_expected ex JOIN poller_item pi '
                 'ON pi.local_data_id=ex.local_data_id AND pi.rrd_name=ex.rrd_name WHERE pi.rrd_next_step>0;')
        self.run_spine()
        self.check_complete(devices=3)

    def test_schedule_skips_items_already_due_every_interval(self):
        # An item stepped at the polling interval keeps rrd_next_step 0, so
        # the countdown update leaves it untouched; the others still count down.
        self.seed(37, 10)
        self.sql('UPDATE poller_item SET rrd_step=1800 WHERE local_data_id>10001; '
                 'CREATE TABLE audit_item_writes(local_data_id INT); '
                 'CREATE TRIGGER audit_item_write BEFORE UPDATE ON poller_item FOR EACH ROW '
                 'INSERT INTO audit_item_writes VALUES(OLD.local_data_id);')
        self.addCleanup(self.sql, 'DROP TRIGGER IF EXISTS audit_item_write; DROP TABLE IF EXISTS audit_item_writes;')
        self.run_spine()
        self.check_complete()
        self.assertEqual(self.sql('SELECT GROUP_CONCAT(local_data_id) FROM audit_item_writes;'), '10001')
        self.assertEqual(self.sql('SELECT rrd_next_step FROM poller_item WHERE local_data_id=10001;'), '1800')
        self.assertEqual(self.sql('SELECT COUNT(*) FROM poller_item WHERE local_data_id>10001 AND rrd_next_step<>0;'), '0')

    def test_device_zero(self):
        self.seed(13, 10, host=0)
        self.seed(37, 10, host=1)
        self.run_spine()
        self.check_complete(devices=2, device_zero=True)

    def test_device_zero_only_in_its_range(self):
        # poller.php gives device 0 to the process whose range starts at 0;
        # every other concurrent process must leave its items alone.
        for hosts, polled in ((('--first=1', '--last=2'), False), (('--first=0', '--last=1'), True),
                              (('-H', '1,2'), False), (('-H', '2,0,1'), True)):
            with self.subTest(hosts=hosts):
                self.setUp()
                self.seed(13, 10, host=0)
                self.seed(37, 10, host=1)
                self.run_spine(hosts=hosts)
                self.assertEqual(self.result.returncode, 0, self.result.stdout[-3000:])
                device_0 = int(self.sql('SELECT COUNT(*) FROM poller_output WHERE local_data_id<10000;'))
                self.assertEqual(device_0, 13 if polled else 0, self.result.stdout[-3000:])
                self.assertEqual(self.sql('SELECT COUNT(*) FROM poller_output WHERE local_data_id>10000;'), '37')

    def test_output_write_failure(self):
        # A failed write still advances the countdown, as in 1.2.31, so a
        # persistent failure cannot freeze the schedule; only Strict_Mode
        # turns it into a non-zero exit status.
        for strict in (False, True):
            with self.subTest(strict=strict):
                self.setUp()
                self.seed(37, 10)
                self.sql("DELIMITER //\nCREATE TRIGGER injected_write_failure BEFORE INSERT ON poller_output "
                         "FOR EACH ROW BEGIN IF NEW.local_data_id=10037 THEN SIGNAL SQLSTATE '45000' "
                         "SET MESSAGE_TEXT='injected output failure'; END IF; END//\nDELIMITER ;\n")
                self.run_spine(strict=strict)
                self.assertEqual(self.result.returncode, 1 if strict else 0, self.result.stdout[-3000:])
                self.assertEqual(self.sql('SELECT COUNT(*) FROM audit_schedule;'), '1')
                self.assertEqual(self.sql('SELECT COUNT(*) FROM poller_item WHERE rrd_next_step=0;'), '0')
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

    @unittest.skipUnless(icmp_datagram_available(), 'needs root and an ICMP datagram socket on Linux')
    def test_icmp_datagram_ping(self):
        # Passes without CAP_NET_RAW only when the datagram socket is used.
        self.seed(3, 1)
        self.sql('UPDATE host SET availability_method=3,ping_method=1,ping_timeout=1000,ping_retries=1;')
        self.run_spine()
        self.check_complete()
        self.assertEqual(self.sql('SELECT CONCAT(status,":",total_polls,":",failed_polls) FROM host;'), '3:1:0')

    @optional('fault', HAVE_FAULT_BINARY, 'the allocation-failure binary needs a linker with --wrap')
    def test_allocation_failures_and_retry(self):
        for failure in ('target', 'target-once', 'snmp', 'snmp-once'):
            with self.subTest(failure=failure):
                self.setUp()
                self.seed(100, 10)
                self.run_spine(failure=failure, strict=True)
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

    @optional('cacti', os.environ.get('SPINE_TEST_CACTI_ROOT'), 'requires a complete upstream Cacti source tree')
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

    @optional('cacti', os.environ.get('SPINE_TEST_CACTI_ROOT'), 'requires a complete upstream Cacti source tree')
    def test_real_script_server_mixed_with_shell(self):
        self.seed(103, 10, multi=True)
        command = str(self.cacti / 'scripts/ss_spine_regression.php') + ' ss_spine_regression '
        self.sql("UPDATE poller_item SET action=2,arg1=CONCAT('" + command + "',local_data_id) "
                 "WHERE MOD(local_data_id,2)=0;")
        self.run_spine()
        self.check_complete()


if __name__ == '__main__':
    unittest.main(verbosity=2)
