<!-- SPDX-FileCopyrightText: 2026 The Cacti Group -->
<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# Formatting and JSON dependencies

Status: accepted for the current fixed logging interface; revisit when consumers
need general JSON construction/parsing or profiling identifies a formatting
bottleneck. Tracks proposals #571 and #572 and the JSON logging consumer #568.

## Decision

Keep libc's checked formatting interfaces. No measured evidence currently shows
that replacing `snprintf` with `stb_sprintf` improves Spine's polling workload.
The paired-build benchmark job now provides reproducible timing and CPU
measurements for future experiments. Its initial default-logging comparison
does not test `stb_sprintf`, and cannot establish that dependency's benefit.
A replacement would also need to preserve truncation, return-value, floating
point and supported-platform behavior. Performance percentages require a
measured comparison with otherwise identical builds.

Use a small reviewed encoder for the fixed JSON log record containing three
string fields. It escapes controls, quotes and backslashes, validates UTF-8,
checks every capacity boundary and rejects invalid input. Production-linked C
tests and an independent Python JSON parser exercise control bytes, valid and
malformed multibyte sequences, and every output-capacity boundary. Allocation,
formatting and cancellation failures are covered separately.

This choice adds no parser or general JSON object API. Existing capabilities
strings retain their established compatibility contract. Do not extend the
encoder into a general JSON library: reconsider a maintained library such as
Jansson when arbitrary typed/nested data or JSON input is required. Such a
change needs dependency/version/license review, supported-platform builds and
consumer tests. The current decision is based on the narrow implemented
interface, not a claim that handwritten JSON is generally preferable.

## Consequences

There is no new installed library or vendored formatter to maintain. The fixed
encoder remains project-owned security-sensitive code and must retain its
strict parser-backed tests. Timestamp failures use `unknown` explicitly;
normal records use UTC. General JSON features and formatter substitutions stay
out of the implemented interface until their requirements and evidence exist.
