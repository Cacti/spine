#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The Cacti Group
# SPDX-License-Identifier: GPL-2.0-or-later
"""Ensure malformed benchmark evidence cannot be accepted as a result."""
import csv
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from verify_benchmark_record import verify

RECORD = Path(__file__).resolve().parents[2] / "docs/benchmarks/results/2026-10-11-default-logging"


class BenchmarkRecordTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.record = Path(self.temporary.name) / "record"
        shutil.copytree(RECORD, self.record)

    def change_rows(self, transform):
        file = self.record / "cycles.csv"
        with file.open(newline="") as stream:
            reader = csv.DictReader(stream)
            fields, rows = reader.fieldnames, list(reader)
        transform(rows)
        with file.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    def test_measured_record(self):
        verify(self.record)

    def test_missing_cycle(self):
        self.change_rows(lambda rows: rows.pop())
        with self.assertRaisesRegex(ValueError, "missing cycle"):
            verify(self.record)

    def test_duplicate_cycle(self):
        self.change_rows(lambda rows: rows.append(rows[0]))
        with self.assertRaisesRegex(ValueError, "duplicate cycle"):
            verify(self.record)

    def test_nonfinite_cpu(self):
        self.change_rows(lambda rows: rows[0].update(cpu_seconds="NaN"))
        with self.assertRaisesRegex(ValueError, "invalid cycle measurement"):
            verify(self.record)

    def test_incorrect_cpu_accounting(self):
        self.change_rows(lambda rows: rows[0].update(cpu_percent="100"))
        with self.assertRaisesRegex(ValueError, "CPU percentage disagrees"):
            verify(self.record)

    def test_incomplete_run(self):
        file = self.record / "metadata.json"
        data = json.loads(file.read_text())
        data["status"] = "incomplete"
        file.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "benchmark is incomplete"):
            verify(self.record)

    def test_unmeasured_summary(self):
        file = self.record / "summary.json"
        data = json.loads(file.read_text())
        data["elapsed_seconds"]["candidate"]["median"] = 0.1
        file.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "summary disagrees"):
            verify(self.record)


if __name__ == "__main__":
    unittest.main()
