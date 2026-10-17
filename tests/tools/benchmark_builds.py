#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The Cacti Group
# SPDX-License-Identifier: GPL-2.0-or-later
"""Measure paired full polling cycles against disposable loopback fixtures."""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import statistics
import subprocess
import time


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--pairs", type=int, default=20)
    parser.add_argument("--warmup", type=int, default=2)
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--devices", type=int, default=64)
    parser.add_argument("--items", type=int, default=16)
    parser.add_argument("--output", type=Path, default=Path("benchmark-results"))
    args = parser.parse_args()
    if not (2 <= args.pairs <= 200 and 0 <= args.warmup <= 20
            and 1 <= args.threads <= 100 and 1 <= args.devices <= 1000
            and 1 <= args.items <= 1000):
        parser.error("benchmark dimensions are outside supported bounds")
    binaries = {"baseline": args.baseline.resolve(), "candidate": args.candidate.resolve()}
    if any(not os.access(binary, os.X_OK) for binary in binaries.values()):
        parser.error("both builds must be executable")
    args.output.mkdir(parents=True, exist_ok=False)
    output = args.output.resolve()
    (output / "metadata.json").write_text('{"status": "incomplete"}\n')
    root = Path(__file__).resolve().parents[2]
    mysql = ["mariadb", "--protocol=TCP", "--host=127.0.0.1", "--user=root", "--batch", "--skip-column-names"]

    def sql(statement):
        return subprocess.run(mysql, input=statement, text=True, check=True,
                              capture_output=True, timeout=30).stdout.strip()

    server_tls = sql("SHOW VARIABLES LIKE 'have_ssl';")
    if server_tls not in ("have_ssl\tDISABLED", "have_ssl\tNO"):
        raise RuntimeError("this fixture requires a disposable server with TLS disabled")
    sql("CREATE USER IF NOT EXISTS 'spine_benchmark'@'127.0.0.1' IDENTIFIED BY 'benchmark-fixture-only'; "
        "CREATE USER IF NOT EXISTS 'spine_benchmark'@'localhost' IDENTIFIED BY 'benchmark-fixture-only'; "
        "GRANT SELECT,INSERT,UPDATE,DELETE ON spine_benchmark.* TO 'spine_benchmark'@'127.0.0.1'; "
        "GRANT SELECT,INSERT,UPDATE,DELETE ON spine_benchmark.* TO 'spine_benchmark'@'localhost';")

    # Only this explicitly named disposable schema is ever modified.
    schema = "".join((root / "tests/fixtures" / name).read_text()
                     for name in ("configuration.sql", "poller.sql"))
    workload = ["UPDATE poller SET threads=%d WHERE id=1;" % args.threads,
                "INSERT INTO settings VALUES ('log_destination','2'),('log_verbosity','1'),('poller_interval','60');"]
    for device in range(1, args.devices + 1):
        workload.append("INSERT INTO host(id,hostname,snmp_community,snmp_version,snmp_port,availability_method,max_oids) "
                        f"VALUES({device},'127.0.0.1','regression',2,1161,0,16);")
        for item in range(args.items):
            identifier = (device - 1) * args.items + item + 1
            workload.append("INSERT INTO poller_item(local_data_id,host_id,action,hostname,snmp_community,snmp_version,snmp_port,snmp_timeout,rrd_name,arg1) "
                            f"VALUES({identifier},{device},0,'127.0.0.1','regression',2,1161,1000,'value','.1.3.6.1.2.1.1.7.0');")
    fixture = "SET SESSION sql_mode='NO_ENGINE_SUBSTITUTION'; DROP DATABASE IF EXISTS spine_benchmark; CREATE DATABASE spine_benchmark; USE spine_benchmark;\n" + schema + "\n" + "\n".join(workload)
    (output / "fixture.sql").write_text(fixture)
    config = output / "spine.conf"
    config.write_text("DB_Host 127.0.0.1\nDB_Database spine_benchmark\nDB_User spine_benchmark\nDB_Pass benchmark-fixture-only\nDB_Port 3306\nDB_UseSSL 0\nCacti_Log " + str(output / "spine.log") + "\n")
    agent_config = output / "snmpd.conf"
    agent_config.write_text("agentaddress udp:127.0.0.1:1161\nrocommunity regression 127.0.0.1\nsysServices 72\n")
    metadata = {"status": "incomplete", "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "platform": platform.platform(), "machine": platform.machine(),
                "cpu_count": os.cpu_count(), "threads": args.threads, "devices": args.devices,
                "items_per_device": args.items, "pairs": args.pairs, "warmup_pairs": args.warmup,
                "tls": "disabled on both builds and the loopback disposable server",
                "server_tls": server_tls,
                "order": "alternating AB/BA", "fixture_sha256": digest(output / "fixture.sql"),
                "config_sha256": digest(config), "agent_config_sha256": digest(agent_config),
                "binary_sha256": {name: digest(binary) for name, binary in binaries.items()},
                "database_version": sql("SELECT VERSION();"),
                "snmpd_version": subprocess.run(["snmpd", "--version"], capture_output=True, text=True, check=True).stdout.strip(),
                "cpu_scope": "Spine process and its children; server and SNMP agent CPU excluded"}
    metadata_file = output / "metadata.json"
    metadata_file.write_text(json.dumps(metadata, indent=2) + "\n")
    rows = []
    with (output / "agent.log").open("w") as agent_log:
        agent = subprocess.Popen(["snmpd", "-f", "-Lo", "-C", "-c", str(agent_config)], stdout=agent_log, stderr=subprocess.STDOUT)
        try:
            for _ in range(50):
                if agent.poll() is not None:
                    raise RuntimeError("owned SNMP agent exited; check for a port collision")
                probe = subprocess.run(["snmpget", "-v2c", "-c", "regression", "-t", "0.1", "-r", "0", "-Oqv", "127.0.0.1:1161", ".1.3.6.1.2.1.1.7.0"], capture_output=True, text=True)
                if probe.returncode == 0 and probe.stdout.strip() == "72":
                    time.sleep(0.2)
                    if agent.poll() is not None:
                        raise RuntimeError("owned SNMP agent failed to bind")
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError("owned SNMP agent did not become ready")
            with (output / "cycles.csv").open("w", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=["pair", "position", "build", "warmup", "elapsed_seconds", "user_seconds", "system_seconds", "cpu_seconds", "cpu_percent"])
                writer.writeheader()
                for pair in range(args.warmup + args.pairs):
                    order = ("baseline", "candidate") if pair % 2 == 0 else ("candidate", "baseline")
                    for position, name in enumerate(order):
                        sql(fixture)  # Reset ALL mutable polling state outside the timed region.
                        with (output / f"cycle-{pair:03d}-{name}.log").open("w") as log:
                            before = resource.getrusage(resource.RUSAGE_CHILDREN)
                            start = time.perf_counter()
                            subprocess.run([str(binaries[name]), "--conf", str(config), "-p", "1", "-t", str(args.threads), "--mode=online", "-O", "poller_interval:60", "-O", "active_profiles:1", "-S", "-V", "1"], stdout=log, stderr=subprocess.STDOUT, check=True, timeout=120)
                            elapsed = time.perf_counter() - start
                            after = resource.getrusage(resource.RUSAGE_CHILDREN)
                        expected = args.devices * args.items
                        counts = sql("USE spine_benchmark; SELECT COUNT(*),SUM(output='72'),COUNT(DISTINCT local_data_id) FROM poller_output;")
                        if counts != f"{expected}\t{expected}\t{expected}":
                            raise RuntimeError(f"{name} polling output failed validation: {counts}")
                        user = after.ru_utime - before.ru_utime
                        system = after.ru_stime - before.ru_stime
                        row = dict(pair=pair, position=position, build=name, warmup=pair < args.warmup,
                                   elapsed_seconds=elapsed, user_seconds=user, system_seconds=system,
                                   cpu_seconds=user + system,
                                   cpu_percent=100 * (user + system) / elapsed)
                        writer.writerow(row)
                        stream.flush()
                        if pair >= args.warmup:
                            rows.append(row)
        finally:
            agent.terminate()
            try:
                agent.wait(timeout=5)
            except subprocess.TimeoutExpired:
                agent.kill()
                agent.wait()
    summary = {}
    for metric in ("elapsed_seconds", "user_seconds", "system_seconds", "cpu_seconds", "cpu_percent"):
        values = {name: [row[metric] for row in rows if row["build"] == name] for name in binaries}
        summary[metric] = {name: {"median": statistics.median(data), "minimum": min(data), "maximum": max(data)} for name, data in values.items()}
        paired = [candidate - baseline for baseline, candidate in zip(values["baseline"], values["candidate"])]
        summary[metric]["median_paired_delta"] = statistics.median(paired)
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    metadata["status"] = "complete"
    metadata_file.write_text(json.dumps(metadata, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
