#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The Cacti Group
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Check the shipped encoder against Python JSON and strict UTF-8 decoding."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
DRIVER = r'''#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "log/log.h"
int main(int argc, char **argv) {
    char output[4098];
    size_t capacity;
    assert(argc == 3);
    assert(!spine_json_log_record(NULL, 1, "now", "INFO", "x"));
    assert(!spine_json_log_record(output, 0, "now", "INFO", "x"));
    assert(!spine_json_log_record(output, sizeof(output), NULL, "INFO", "x"));
    assert(!spine_json_log_record(output, sizeof(output), "now", NULL, "x"));
    assert(!spine_json_log_record(output, sizeof(output), "now", "INFO", NULL));
    capacity = strtoul(argv[2], NULL, 10);
    assert(capacity <= 4096);
    memset(output, 0xa5, sizeof(output));
    if (!spine_json_log_record(output, capacity, "time\"\n", "INFO", argv[1])) {
        assert((unsigned char)output[capacity] == 0xa5);
        if (capacity) assert(output[0] == 0);
        return 3;
    }
    assert((unsigned char)output[capacity] == 0xa5);
    return fputs(output, stdout) == EOF;
}
'''


class EncoderContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="spine-json-contracts-")
        cls.build = Path(cls.directory.name)
        cls.driver = cls.build / "driver.c"
        cls.driver.write_text(DRIVER)
        cls.program = cls.build / "encoder"
        compiler = shlex.split(os.environ.get("CC", "cc"))
        flags = shlex.split(os.environ.get("SPINE_JSON_TEST_CFLAGS", ""))
        subprocess.run(compiler + ["-std=gnu17", "-Wall", "-Wextra", "-Werror"] + flags +
                       ["-I", str(ROOT / "src"), str(cls.driver), str(ROOT / "src/log/json.c"),
                        "-o", str(cls.program)], check=True, cwd=cls.build)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def encode(self, value, capacity=4096):
        return subprocess.run([os.fsencode(self.program), value, str(capacity).encode()],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)

    def test_json_round_trip(self):
        values = [b"", b"ordinary text", b'quote" slash\\', bytes(range(1, 32)) + b"\x7f",
                  "å漢字😀".encode(), b"\xc2\x80", b"\xdf\xbf", b"\xe0\xa0\x80",
                  b"\xed\x9f\xbf", b"\xef\xbf\xbf", b"\xf0\x90\x80\x80", b"\xf4\x8f\xbf\xbf"]
        for value in values:
            with self.subTest(value=value):
                result = self.encode(value)
                self.assertEqual(result.returncode, 0, result.stderr)
                record = json.loads(result.stdout)
                self.assertEqual(record, {"timestamp": 'time"\n', "severity": "INFO",
                                          "message": value.decode("utf-8")})
                self.assertEqual(result.stdout.count(b"\n"), 1)

    @staticmethod
    def replace_invalid(value):
        """Expected text: each byte that does not begin a valid sequence is U+FFFD."""
        out, index = [], 0
        while index < len(value):
            for width in (1, 2, 3, 4):
                try:
                    out.append(value[index:index + width].decode("utf-8"))
                    index += width
                    break
                except UnicodeDecodeError:
                    continue
            else:
                out.append("\ufffd")
                index += 1
        return "".join(out)

    def test_invalid_utf8_is_replaced(self):
        values = [bytes([value]) for value in range(128, 256)]
        values += [b"\xc0\xaf", b"\xc1\xbf", b"\xe1\x80", b"\xf1\x80\x80",
                   b"\xe0\x9f\xbf", b"\xed\xa0\x80", b"\xf0\x8f\xbf\xbf",
                   b"\xf4\x90\x80\x80", b"\xe1A\x80", b"\xe1\xc0\x80", b"\xe1\x80A",
                   b"ok \xff tail", b"\xe6\xbc"]
        for value in values:
            with self.subTest(value=value):
                with self.assertRaises(UnicodeDecodeError):
                    value.decode("utf-8")
                result = self.encode(value)
                self.assertEqual(result.returncode, 0, result.stderr)
                record = json.loads(result.stdout)
                self.assertEqual(record["message"], self.replace_invalid(value))
                self.assertEqual(result.stdout.count(b"\n"), 1)

    def test_every_capacity_boundary(self):
        for value in [b"", b'quote" slash\\', bytes(range(1, 32)), "漢字".encode()]:
            full = self.encode(value)
            self.assertEqual(full.returncode, 0)
            for capacity in range(len(full.stdout) + 1):
                result = self.encode(value, capacity)
                self.assertEqual(result.returncode, 3, (capacity, result.stderr))
            exact = self.encode(value, len(full.stdout) + 1)
            self.assertEqual(exact.returncode, 0, exact.stderr)
            self.assertEqual(exact.stdout, full.stdout)


if __name__ == "__main__":
    unittest.main()
