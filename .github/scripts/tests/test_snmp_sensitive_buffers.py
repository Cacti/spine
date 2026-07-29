#!/usr/bin/env python3
from __future__ import annotations

import re
import unittest
from pathlib import Path


SNMP_C = Path(__file__).resolve().parents[3] / "src" / "snmp.c"


class SnmpSensitiveBufferTest(unittest.TestCase):
	def test_snmp_host_init_does_not_zero_caller_owned_passphrases(self) -> None:
		source = SNMP_C.read_text(encoding="utf-8")
		body_match = re.search(
			r"void \*snmp_host_init\([^)]*\) \{(?P<body>.*?)\n\}\n\n/\*! \\fn void snmp_host_cleanup",
			source,
			re.S,
		)
		self.assertIsNotNone(body_match)
		body = body_match.group("body")

		for parameter in ("snmp_password", "snmp_priv_passphrase"):
			self.assertIsNone(
				re.search(rf"\bmemset\s*\(\s*{parameter}\b", body),
				f"snmp_host_init must not zero caller-owned {parameter}",
			)

		self.assertRegex(body, r"\bmemset\s*\(\s*Apsz\b")
		self.assertRegex(body, r"\bmemset\s*\(\s*Xpsz\b")


if __name__ == "__main__":
	unittest.main()
