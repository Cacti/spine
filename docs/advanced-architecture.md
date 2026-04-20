# Asynchronous Architecture

Spine 1.3+ features a modern, asynchronous polling engine built on **libuv**. This architecture replaces the traditional 1-thread-per-host model with a highly efficient event loop.

## Stage-Based Pipeline (SOLID)

The poller orchestrates device polling through an extensible, non-blocking pipeline:

1. **DNS (Async)**: Hostnames are resolved using `c-ares`, allowing thousands of resolutions to happen concurrently without blocking the main loop.
2. **PING (Async)**: ICMP availability checks are performed using non-blocking raw sockets.
3. **SNMP (Async)**: SNMP GET requests are multiplexed on the event loop via a dedicated `uv_poll_t` bridge to Net-SNMP.
4. **SCRIPTS (Async)**: External commands and the PHP Script Server are managed via `uv_spawn` and `uv_pipe_t`, providing efficient IPC with backpressure.
5. **FLUSH (Async)**: Results are enqueued into a batching buffer.

## Smart SQL Batching

To minimize database transaction overhead, Spine implements a high-watermark buffering system:

- **Buffer**: Results are accumulated into multi-row `INSERT` fragments.
- **Trigger**: The buffer is flushed to MariaDB/MySQL when it reaches a configured size or after 500ms (whichever comes first).
- **Non-Blocking**: Database writes are performed using the MariaDB non-blocking API, ensuring the event loop never stalls while waiting for DB I/O.

## Observability

Internal counters (pipeline-stage latency, queue depth, completed polls
per cycle) are tracked via `src/telemetry.c`. A query interface on top
of those counters is a follow-up; this document previously described a
Unix socket at `/var/run/spine/telemetry.sock` that was never wired.
