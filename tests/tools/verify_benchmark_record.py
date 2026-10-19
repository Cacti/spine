#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The Cacti Group
# SPDX-License-Identifier: GPL-2.0-or-later
"""Independently verify a completed benchmark's samples and summary."""
import csv
import json
import math
from pathlib import Path
import statistics
import sys


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify(directory):
    directory = Path(directory)
    metadata = json.loads((directory / "metadata.json").read_text())
    require(metadata["status"] == "complete", "benchmark is incomplete")
    pairs, warmup = metadata["pairs"], metadata["warmup_pairs"]
    require(type(pairs) is int and pairs >= 2 and type(warmup) is int and warmup >= 0,
            "invalid sample dimensions")
    samples = {}
    metrics = ("elapsed_seconds", "user_seconds", "system_seconds", "cpu_seconds", "cpu_percent")
    with (directory / "cycles.csv").open(newline="") as stream:
        for row in csv.DictReader(stream):
            pair, name = int(row["pair"]), row["build"]
            require(0 <= pair < pairs + warmup and name in ("baseline", "candidate"), "invalid sample key")
            require((pair, name) not in samples, "duplicate cycle")
            require(row["warmup"] == str(pair < warmup), "invalid warmup flag")
            expected_first = "baseline" if pair % 2 == 0 else "candidate"
            require(int(row["position"]) == int(name != expected_first), "invalid alternating order")
            values = {metric: float(row[metric]) for metric in metrics}
            require(all(math.isfinite(value) and value >= 0 for value in values.values())
                    and values["elapsed_seconds"] > 0, "invalid cycle measurement")
            require(math.isclose(values["cpu_seconds"], values["user_seconds"] + values["system_seconds"], abs_tol=1e-12), "CPU total disagrees")
            require(math.isclose(values["cpu_percent"], 100 * values["cpu_seconds"] / values["elapsed_seconds"], abs_tol=1e-12), "CPU percentage disagrees")
            samples[pair, name] = values
    require(len(samples) == 2 * (pairs + warmup), "missing cycle")
    summary = json.loads((directory / "summary.json").read_text())
    for metric in metrics:
        values = {name: [samples[pair, name][metric] for pair in range(warmup, pairs + warmup)]
                  for name in ("baseline", "candidate")}
        for name, data in values.items():
            for key, expected in (("median", statistics.median(data)), ("minimum", min(data)), ("maximum", max(data))):
                require(math.isclose(summary[metric][name][key], expected, abs_tol=1e-12), "summary disagrees with measured cycles")
        expected = statistics.median(candidate - baseline for baseline, candidate
                                     in zip(values["baseline"], values["candidate"]))
        require(math.isclose(summary[metric]["median_paired_delta"], expected, abs_tol=1e-12), "paired delta disagrees")


if __name__ == "__main__":
    verify(sys.argv[1])
    print("Benchmark record verified")
